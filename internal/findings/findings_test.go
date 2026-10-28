package findings_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	ann "emeland.io/modelsrv-otel-filter/internal/annotations"
	"emeland.io/modelsrv-otel-filter/internal/findings"
	"go.emeland.io/modelsrv/pkg/events"
	"go.emeland.io/modelsrv/pkg/model"
	"go.emeland.io/modelsrv/pkg/model/finding"
)

func TestFindings(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Findings Suite")
}

func newModel() model.Model {
	m, err := model.NewModel(events.NewListSink())
	Expect(err).ToNot(HaveOccurred())
	findings.EnsureFindingTypes(m, zap.NewNop().Sugar())
	return m
}

var _ = Describe("Reconciler", func() {
	var (
		m             model.Model
		r             *findings.Reconciler
		apiInstanceID uuid.UUID
		threshold     = 30 * 24 * time.Hour
	)

	BeforeEach(func() {
		m = newModel()
		r = findings.NewReconciler(threshold, nil)
		apiInstanceID = uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	})

	It("raises CertificateExpiringSoon when remaining is within threshold", func() {
		r.ReconcileObservation(m, apiInstanceID, map[string]string{
			ann.Remaining: "86400", // 1 day
		})
		f := m.GetFindingById(findings.FindingID(apiInstanceID, finding.CertificateExpiringSoon))
		Expect(f).ToNot(BeNil())
		Expect(f.GetFindingTypeId()).To(Equal(finding.TypeIDForKind(finding.CertificateExpiringSoon)))
	})

	It("raises CertificateExpired when remaining <= 0", func() {
		r.ReconcileObservation(m, apiInstanceID, map[string]string{
			ann.Remaining: "-3600",
		})
		f := m.GetFindingById(findings.FindingID(apiInstanceID, finding.CertificateExpired))
		Expect(f).ToNot(BeNil())
	})

	It("clears findings when remaining is above threshold", func() {
		r.ReconcileObservation(m, apiInstanceID, map[string]string{ann.Remaining: "86400"})
		Expect(m.GetFindingById(findings.FindingID(apiInstanceID, finding.CertificateExpiringSoon))).ToNot(BeNil())

		r.ReconcileObservation(m, apiInstanceID, map[string]string{ann.Remaining: "7776000"}) // 90 days
		Expect(m.GetFindingById(findings.FindingID(apiInstanceID, finding.CertificateExpiringSoon))).To(BeNil())
	})

	It("raises CertificateProbeFailed on error annotation", func() {
		r.ReconcileObservation(m, apiInstanceID, map[string]string{
			ann.Error: "connection refused",
		})
		f := m.GetFindingById(findings.FindingID(apiInstanceID, finding.CertificateProbeFailed))
		Expect(f).ToNot(BeNil())
		Expect(f.GetDescription()).To(ContainSubstring("connection refused"))
	})

	It("uses deterministic finding IDs matching endpointprobe", func() {
		expected := uuid.NewSHA1(
			uuid.MustParse("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
			append(apiInstanceID[:], []byte(finding.CertificateExpiringSoon)...),
		)
		Expect(findings.FindingID(apiInstanceID, finding.CertificateExpiringSoon)).To(Equal(expected))
	})
})
