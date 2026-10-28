// Package filter implements the modelsrv event filter that syncs OTel collector
// config from ApiInstance certificate annotations, merges probe observations,
// and authors certificate Findings.
package filter

import (
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"

	ann "emeland.io/modelsrv-otel-filter/internal/annotations"
	"emeland.io/modelsrv-otel-filter/internal/findings"
	"emeland.io/modelsrv-otel-filter/internal/otelconfig"
	"emeland.io/modelsrv-otel-filter/internal/targets"
	"go.emeland.io/modelsrv/pkg/eventfilter"
	"go.emeland.io/modelsrv/pkg/events"
	"go.emeland.io/modelsrv/pkg/model"
	"go.emeland.io/modelsrv/pkg/model/api"
	"go.emeland.io/modelsrv/pkg/model/system"
)

// Config holds dependencies for [New].
type Config struct {
	Writer     *otelconfig.ConfigWriter
	Reconciler *findings.Reconciler
	Logger     *zap.SugaredLogger
}

// certFilter is the stateful ApiInstance event filter.
type certFilter struct {
	writer     *otelconfig.ConfigWriter
	reconciler *findings.Reconciler
	log        *zap.SugaredLogger

	mu           sync.Mutex
	snapshots    map[uuid.UUID]api.ApiInstance // last upstream (non-otel) snapshot
	observations map[uuid.UUID]map[string]string
	publishing   bool // reentrancy guard while publishing a merge
}

// New returns a passthrough event filter that maintains OTel collector config,
// merges certificate observations onto ApiInstances, and authors Findings.
func New(cfg Config) eventfilter.Filter {
	log := cfg.Logger
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	f := &certFilter{
		writer:       cfg.Writer,
		reconciler:   cfg.Reconciler,
		log:          log,
		snapshots:    make(map[uuid.UUID]api.ApiInstance),
		observations: make(map[uuid.UUID]map[string]string),
	}
	return eventfilter.Filter{
		DisplayName: "otel-certificate-filter",
		Description: "Maintains OTel http_check config from certificate.https-endpoint annotations and authors certificate Findings",
		Fn:          f.apply,
	}
}

func (f *certFilter) apply(m model.Model, ev events.Event) []events.Event {
	if ev.ResourceType != events.APIInstanceResource {
		return []events.Event{ev}
	}

	f.mu.Lock()
	if f.publishing {
		f.mu.Unlock()
		return []events.Event{ev}
	}
	f.mu.Unlock()

	switch ev.Operation {
	case events.DeleteOperation:
		return f.handleDelete(m, ev)
	case events.CreateOperation, events.UpdateOperation:
		return f.handleUpsert(m, ev)
	default:
		return []events.Event{ev}
	}
}

func (f *certFilter) handleDelete(m model.Model, ev events.Event) []events.Event {
	id := ev.ResourceId
	f.mu.Lock()
	delete(f.snapshots, id)
	delete(f.observations, id)
	f.mu.Unlock()

	if f.writer != nil {
		f.writer.Remove(id)
	}
	if f.reconciler != nil {
		f.reconciler.Clear(m, id)
	}
	return []events.Event{ev}
}

func (f *certFilter) handleUpsert(m model.Model, ev events.Event) []events.Event {
	if len(ev.Objects) == 0 {
		return []events.Event{ev}
	}
	ai, ok := ev.Objects[0].(api.ApiInstance)
	if !ok {
		return []events.Event{ev}
	}

	id := ai.GetInstanceId()
	if isOTelObservation(ai) {
		return f.handleObservation(m, ai, id)
	}
	return f.handleUpstream(m, ai, id)
}

func (f *certFilter) handleObservation(m model.Model, ai api.ApiInstance, id uuid.UUID) []events.Event {
	obs := extractObservation(ai)

	f.mu.Lock()
	f.observations[id] = obs
	snapshot, hasSnapshot := f.snapshots[id]
	f.mu.Unlock()

	if !hasSnapshot {
		// Apply already stored the incomplete observation object; remove it.
		// publishing=true so the resulting Delete does not clear the held observation.
		f.mu.Lock()
		f.publishing = true
		f.mu.Unlock()
		if err := m.DeleteApiInstanceById(id); err != nil {
			f.log.Warnw("failed to drop premature observation ApiInstance", "apiInstanceId", id, "error", err)
		}
		f.mu.Lock()
		f.publishing = false
		f.mu.Unlock()
		f.log.Debugw("holding certificate observation until ApiInstance snapshot arrives", "apiInstanceId", id)
		return nil
	}

	f.publishMerge(m, snapshot, obs)
	return nil
}

func (f *certFilter) handleUpstream(m model.Model, ai api.ApiInstance, id uuid.UUID) []events.Event {
	snapshot := cloneApiInstance(ai)

	f.mu.Lock()
	f.snapshots[id] = snapshot
	obs := f.observations[id]
	f.mu.Unlock()

	f.syncConfig(snapshot)

	f.publishMerge(m, snapshot, obs)
	return nil
}

func (f *certFilter) syncConfig(ai api.ApiInstance) {
	if f.writer == nil {
		return
	}
	target, hasTarget, err := targets.TargetFromApiInstance(ai)
	if err != nil {
		f.log.Warnw("invalid certificate.https-endpoint; removing target",
			"apiInstanceId", ai.GetInstanceId(),
			"error", err,
		)
		f.writer.Remove(ai.GetInstanceId())
		return
	}
	if !hasTarget {
		f.writer.Remove(ai.GetInstanceId())
		return
	}
	f.writer.Upsert(target)
}

func (f *certFilter) publishMerge(m model.Model, snapshot api.ApiInstance, obs map[string]string) {
	merged := mergeApiInstance(snapshot, obs)

	f.mu.Lock()
	f.publishing = true
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.publishing = false
		f.mu.Unlock()
	}()

	if err := m.AddApiInstance(merged); err != nil {
		f.log.Warnw("failed to publish merged ApiInstance",
			"apiInstanceId", snapshot.GetInstanceId(),
			"error", err,
		)
		return
	}

	if f.reconciler != nil {
		if len(obs) == 0 {
			f.reconciler.Clear(m, snapshot.GetInstanceId())
		} else {
			f.reconciler.ReconcileObservation(m, snapshot.GetInstanceId(), obs)
		}
	}
}

func isOTelObservation(ai api.ApiInstance) bool {
	return ai.GetAnnotations().GetValue(ann.Source) == ann.SourceOTel
}

func extractObservation(ai api.ApiInstance) map[string]string {
	src := ai.GetAnnotations()
	out := make(map[string]string)
	for _, key := range ann.ObservationKeys {
		if v := src.GetValue(key); v != "" {
			out[key] = v
		}
	}
	return out
}

func mergeApiInstance(snapshot api.ApiInstance, obs map[string]string) api.ApiInstance {
	merged := cloneApiInstance(snapshot)
	anns := merged.GetAnnotations()

	for _, key := range ann.ObservationKeys {
		anns.Delete(key)
	}
	anns.Delete(ann.Source)

	for k, v := range obs {
		if k == ann.Source {
			continue
		}
		anns.Add(k, v)
	}
	return merged
}

func cloneApiInstance(src api.ApiInstance) api.ApiInstance {
	dst := api.NewApiInstance(src.GetInstanceId())
	dst.SetDisplayName(src.GetDisplayName())
	if ref := src.GetApiRef(); ref != nil {
		dst.SetApiRef(&api.ApiRef{ApiID: ref.ApiID})
	}
	if ref := src.GetSystemInstance(); ref != nil {
		dst.SetSystemInstance(&system.SystemInstanceRef{InstanceId: ref.InstanceId})
	}
	for k := range src.GetAnnotations().GetKeys() {
		if k == ann.Source {
			continue
		}
		dst.GetAnnotations().Add(k, src.GetAnnotations().GetValue(k))
	}
	return dst
}
