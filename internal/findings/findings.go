// Package findings maps certificate probe observations to EmELand Finding
// resources using the same decision table and deterministic IDs as
// modelsrv's native endpointprobe path.
package findings

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	ann "emeland.io/modelsrv-otel-filter/internal/annotations"
	"go.emeland.io/modelsrv/pkg/events"
	"go.emeland.io/modelsrv/pkg/model"
	"go.emeland.io/modelsrv/pkg/model/common"
	"go.emeland.io/modelsrv/pkg/model/finding"
)

// certFindingNamespace mirrors endpointprobe so finding IDs match between
// the native certprobe and the OTel filter path.
var certFindingNamespace = uuid.MustParse("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

const certFindingDisplayName = "Certificate expiry check"

var certFindingKinds = []finding.FindingKind{
	finding.CertificateExpiringSoon,
	finding.CertificateExpired,
	finding.CertificateProbeFailed,
}

// Reconciler upserts or deletes certificate findings for an ApiInstance.
type Reconciler struct {
	threshold time.Duration
	log       *zap.SugaredLogger
}

// NewReconciler returns a Reconciler with the given expiry threshold.
func NewReconciler(threshold time.Duration, log *zap.SugaredLogger) *Reconciler {
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	if threshold <= 0 {
		threshold = 30 * 24 * time.Hour
	}
	return &Reconciler{threshold: threshold, log: log}
}

// EnsureFindingTypes registers well-known certificate FindingTypes.
func EnsureFindingTypes(m model.Model, log *zap.SugaredLogger) {
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	for _, kind := range certFindingKinds {
		id := finding.TypeIDForKind(kind)
		if ft := m.GetFindingTypeById(id); ft != nil {
			continue
		}
		ft := finding.NewFindingType(id)
		ft.SetDisplayName(string(kind))
		if desc := finding.DescriptionForKind(kind); desc != "" {
			ft.SetDescription(desc)
		}
		if err := m.AddFindingType(ft); err != nil {
			log.Warnw("failed to register FindingType", "kind", kind, "error", err)
		}
	}
}

// ReconcileObservation applies findings from observation annotation values.
// observation is the map of certificate observation keys (may include Error).
func (r *Reconciler) ReconcileObservation(m model.Model, apiInstanceID uuid.UUID, observation map[string]string) {
	if errMsg := observation[ann.Error]; errMsg != "" {
		r.upsert(m, apiInstanceID, finding.CertificateProbeFailed,
			fmt.Sprintf("CertificateProbeFailed: probe of ApiInstance %s failed: %s", apiInstanceID, errMsg))
		r.deleteKinds(m, apiInstanceID, finding.CertificateExpiringSoon, finding.CertificateExpired)
		return
	}

	rawRemaining, ok := observation[ann.Remaining]
	if !ok || rawRemaining == "" {
		r.deleteAll(m, apiInstanceID)
		return
	}

	secs, err := strconv.ParseFloat(rawRemaining, 64)
	if err != nil {
		r.log.Warnw("invalid certificate.remaining", "apiInstanceId", apiInstanceID, "value", rawRemaining, "error", err)
		return
	}
	remaining := time.Duration(secs * float64(time.Second))

	switch {
	case remaining > r.threshold:
		r.deleteAll(m, apiInstanceID)
	case remaining > 0:
		desc := fmt.Sprintf(
			"CertificateExpiringSoon: ApiInstance %s certificate expires in %s (threshold %s)",
			apiInstanceID, remaining.Round(time.Second), r.threshold,
		)
		r.upsert(m, apiInstanceID, finding.CertificateExpiringSoon, desc)
		r.deleteKinds(m, apiInstanceID, finding.CertificateExpired, finding.CertificateProbeFailed)
	default:
		desc := fmt.Sprintf(
			"CertificateExpired: ApiInstance %s certificate expired %s ago",
			apiInstanceID, (-remaining).Round(time.Second),
		)
		r.upsert(m, apiInstanceID, finding.CertificateExpired, desc)
		r.deleteKinds(m, apiInstanceID, finding.CertificateExpiringSoon, finding.CertificateProbeFailed)
	}
}

// Clear removes all certificate findings for the ApiInstance.
func (r *Reconciler) Clear(m model.Model, apiInstanceID uuid.UUID) {
	r.deleteAll(m, apiInstanceID)
}

func (r *Reconciler) upsert(m model.Model, apiInstanceID uuid.UUID, kind finding.FindingKind, description string) {
	fID := FindingID(apiInstanceID, kind)
	f := finding.NewFinding(fID)
	f.SetFindingTypeById(finding.TypeIDForKind(kind))
	f.SetDisplayName(certFindingDisplayName)
	f.SetDescription(description)
	f.SetResources([]*common.ResourceRef{
		{ResourceId: apiInstanceID, ResourceType: events.APIInstanceResource},
	})
	if err := m.AddFinding(f); err != nil {
		r.log.Warnw("AddFinding failed", "findingId", fID, "kind", kind, "error", err)
	}
}

func (r *Reconciler) deleteAll(m model.Model, apiInstanceID uuid.UUID) {
	r.deleteKinds(m, apiInstanceID, certFindingKinds...)
}

func (r *Reconciler) deleteKinds(m model.Model, apiInstanceID uuid.UUID, kinds ...finding.FindingKind) {
	for _, kind := range kinds {
		id := FindingID(apiInstanceID, kind)
		if m.GetFindingById(id) == nil {
			continue
		}
		if err := m.DeleteFindingById(id); err != nil && !errors.Is(err, common.ErrFindingNotFound) {
			r.log.Warnw("DeleteFindingById failed", "findingId", id, "kind", kind, "error", err)
		}
	}
}

// FindingID produces the same deterministic UUID as endpointprobe.findingID.
func FindingID(apiInstanceID uuid.UUID, kind finding.FindingKind) uuid.UUID {
	key := append(apiInstanceID[:], []byte(kind)...)
	return uuid.NewSHA1(certFindingNamespace, key)
}
