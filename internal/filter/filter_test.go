package filter_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	ann "emeland.io/modelsrv-otel-filter/internal/annotations"
	"emeland.io/modelsrv-otel-filter/internal/filter"
	"emeland.io/modelsrv-otel-filter/internal/findings"
	"emeland.io/modelsrv-otel-filter/internal/otelconfig"
	"go.emeland.io/modelsrv/pkg/backend"
	"go.emeland.io/modelsrv/pkg/events"
	"go.emeland.io/modelsrv/pkg/model/api"
	"go.emeland.io/modelsrv/pkg/model/finding"
)

func TestFilter(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Filter Suite")
}

func annotatedInstance(id uuid.UUID, endpoint string) api.ApiInstance {
	ai := api.NewApiInstance(id)
	ai.SetDisplayName("test-api")
	if endpoint != "" {
		ai.GetAnnotations().Add(ann.HTTPSEndpoint, endpoint)
	}
	return ai
}

func observationInstance(id uuid.UUID, remaining string) api.ApiInstance {
	ai := api.NewApiInstance(id)
	ai.GetAnnotations().Add(ann.Source, ann.SourceOTel)
	ai.GetAnnotations().Add(ann.Remaining, remaining)
	ai.GetAnnotations().Add(ann.ProbedAt, time.Now().UTC().Format(time.RFC3339))
	return ai
}

var _ = Describe("Certificate filter", func() {
	var (
		b      backend.Backend
		writer *otelconfig.ConfigWriter
		path   string
		id     uuid.UUID
	)

	BeforeEach(func() {
		var err error
		b, err = backend.New()
		Expect(err).ToNot(HaveOccurred())

		path = filepath.Join(GinkgoT().TempDir(), "collector.yaml")
		writer, err = otelconfig.NewConfigWriter(otelconfig.ConfigWriterConfig{
			Path:     path,
			Debounce: time.Hour,
			Logger:   zap.NewNop().Sugar(),
			Opts: otelconfig.CollectorConfigOptions{
				ListenAddr:  "0.0.0.0:24200",
				Subscribers: []string{"http://filter:8080/api"},
			},
		})
		Expect(err).ToNot(HaveOccurred())

		reconciler := findings.NewReconciler(30*24*time.Hour, nil)
		findings.EnsureFindingTypes(b.GetModel(), nil)
		b.GetChain().RegisterFilter(filter.New(filter.Config{
			Writer:     writer,
			Reconciler: reconciler,
			Logger:     zap.NewNop().Sugar(),
		}))

		id = uuid.MustParse("88888888-0000-4000-8000-000000000001")
	})

	It("writes collector config when an annotated ApiInstance is created", func() {
		ai := annotatedInstance(id, "https://payments.example.com/health")
		Expect(b.GetModel().Apply(events.Event{
			ResourceType: events.APIInstanceResource,
			Operation:    events.CreateOperation,
			ResourceId:   id,
			Objects:      []any{ai},
		})).To(Succeed())
		Expect(writer.Flush()).To(Succeed())

		raw, err := os.ReadFile(path)
		Expect(err).ToNot(HaveOccurred())
		var parsed map[string]any
		Expect(yaml.Unmarshal(raw, &parsed)).To(Succeed())
		receivers := parsed["receivers"].(map[string]any)
		httpCheck := receivers["http_check"].(map[string]any)
		targetsList := httpCheck["targets"].([]any)
		Expect(targetsList).To(HaveLen(1))
		Expect(targetsList[0].(map[string]any)["endpoint"]).To(Equal("https://payments.example.com:443/health"))
	})

	It("merges observation annotations and raises a finding", func() {
		ai := annotatedInstance(id, "https://payments.example.com/health")
		Expect(b.GetModel().Apply(events.Event{
			ResourceType: events.APIInstanceResource,
			Operation:    events.CreateOperation,
			ResourceId:   id,
			Objects:      []any{ai},
		})).To(Succeed())

		obs := observationInstance(id, "86400") // 1 day -> ExpiringSoon
		Expect(b.GetModel().Apply(events.Event{
			ResourceType: events.APIInstanceResource,
			Operation:    events.UpdateOperation,
			ResourceId:   id,
			Objects:      []any{obs},
		})).To(Succeed())

		got := b.GetModel().GetApiInstanceById(id)
		Expect(got).ToNot(BeNil())
		Expect(got.GetDisplayName()).To(Equal("test-api"))
		Expect(got.GetAnnotations().GetValue(ann.HTTPSEndpoint)).To(Equal("https://payments.example.com/health"))
		Expect(got.GetAnnotations().GetValue(ann.Remaining)).To(Equal("86400"))
		Expect(got.GetAnnotations().GetValue(ann.Source)).To(BeEmpty())

		f := b.GetModel().GetFindingById(findings.FindingID(id, finding.CertificateExpiringSoon))
		Expect(f).ToNot(BeNil())
	})

	It("holds an observation until the upstream snapshot arrives", func() {
		obs := observationInstance(id, "3600")
		Expect(b.GetModel().Apply(events.Event{
			ResourceType: events.APIInstanceResource,
			Operation:    events.UpdateOperation,
			ResourceId:   id,
			Objects:      []any{obs},
		})).To(Succeed())
		Expect(b.GetModel().GetApiInstanceById(id)).To(BeNil())

		ai := annotatedInstance(id, "https://api.example.com/")
		Expect(b.GetModel().Apply(events.Event{
			ResourceType: events.APIInstanceResource,
			Operation:    events.CreateOperation,
			ResourceId:   id,
			Objects:      []any{ai},
		})).To(Succeed())

		got := b.GetModel().GetApiInstanceById(id)
		Expect(got).ToNot(BeNil())
		Expect(got.GetAnnotations().GetValue(ann.Remaining)).To(Equal("3600"))
		Expect(got.GetDisplayName()).To(Equal("test-api"))
	})

	It("removes the target and findings on delete", func() {
		ai := annotatedInstance(id, "https://payments.example.com/health")
		Expect(b.GetModel().Apply(events.Event{
			ResourceType: events.APIInstanceResource,
			Operation:    events.CreateOperation,
			ResourceId:   id,
			Objects:      []any{ai},
		})).To(Succeed())

		obs := observationInstance(id, "100")
		Expect(b.GetModel().Apply(events.Event{
			ResourceType: events.APIInstanceResource,
			Operation:    events.UpdateOperation,
			ResourceId:   id,
			Objects:      []any{obs},
		})).To(Succeed())
		Expect(b.GetModel().GetFindingById(findings.FindingID(id, finding.CertificateExpiringSoon))).ToNot(BeNil())

		Expect(b.GetModel().Apply(events.Event{
			ResourceType: events.APIInstanceResource,
			Operation:    events.DeleteOperation,
			ResourceId:   id,
		})).To(Succeed())
		Expect(writer.Flush()).To(Succeed())

		Expect(b.GetModel().GetFindingById(findings.FindingID(id, finding.CertificateExpiringSoon))).To(BeNil())

		raw, err := os.ReadFile(path)
		Expect(err).ToNot(HaveOccurred())
		var parsed map[string]any
		Expect(yaml.Unmarshal(raw, &parsed)).To(Succeed())
		receivers := parsed["receivers"].(map[string]any)
		httpCheck := receivers["http_check"].(map[string]any)
		if targetsList, ok := httpCheck["targets"]; ok && targetsList != nil {
			Expect(targetsList.([]any)).To(BeEmpty())
		}
	})
})
