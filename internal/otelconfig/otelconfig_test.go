package otelconfig_test

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

	"emeland.io/modelsrv-otel-filter/internal/otelconfig"
	"emeland.io/modelsrv-otel-filter/internal/targets"
)

func TestOtelConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OtelConfig Suite")
}

var _ = Describe("RenderCollectorConfig", func() {
	It("renders http_check targets and endpoint_mapping without expiry_threshold", func() {
		id := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
		raw, err := otelconfig.RenderCollectorConfig([]targets.ProbeTarget{{
			ApiInstanceID: id,
			URL:           "https://api.example.com:443/health",
			DedupeKey:     "api.example.com:443",
		}}, otelconfig.CollectorConfigOptions{
			CollectionInterval: 5 * time.Minute,
			ListenAddr:         "0.0.0.0:24200",
			Subscribers:        []string{"http://filter:8080/api"},
		})
		Expect(err).ToNot(HaveOccurred())

		var parsed map[string]any
		Expect(yaml.Unmarshal(raw, &parsed)).To(Succeed())

		receivers := parsed["receivers"].(map[string]any)
		httpCheck := receivers["http_check"].(map[string]any)
		Expect(httpCheck["collection_interval"]).To(Equal("5m"))
		targetsList := httpCheck["targets"].([]any)
		Expect(targetsList).To(HaveLen(1))

		exporters := parsed["exporters"].(map[string]any)
		emeland := exporters["emeland"].(map[string]any)
		Expect(emeland).ToNot(HaveKey("expiry_threshold"))
		Expect(emeland["listen_addr"]).To(Equal("0.0.0.0:24200"))
		mapping := emeland["endpoint_mapping"].(map[string]any)
		Expect(mapping["https://api.example.com:443/health"]).To(Equal(id.String()))
		subs := emeland["subscribers"].([]any)
		Expect(subs).To(ContainElement("http://filter:8080/api"))
	})
})

var _ = Describe("ConfigWriter", func() {
	It("writes and updates the collector config file", func() {
		path := filepath.Join(GinkgoT().TempDir(), "collector.yaml")
		w, err := otelconfig.NewConfigWriter(otelconfig.ConfigWriterConfig{
			Path:     path,
			Debounce: time.Hour,
			Logger:   zap.NewNop().Sugar(),
			Opts: otelconfig.CollectorConfigOptions{
				ListenAddr: "0.0.0.0:24200",
			},
		})
		Expect(err).ToNot(HaveOccurred())

		id := uuid.MustParse("bbbbbbbb-0000-4000-8000-000000000001")
		w.Upsert(targets.ProbeTarget{
			ApiInstanceID: id,
			URL:           "https://payments.example.com:443/",
			DedupeKey:     "payments.example.com:443",
		})
		Expect(w.Flush()).To(Succeed())

		raw, err := os.ReadFile(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring("https://payments.example.com:443/"))

		w.Remove(id)
		Expect(w.Flush()).To(Succeed())
		raw, err = os.ReadFile(path)
		Expect(err).ToNot(HaveOccurred())

		var parsed map[string]any
		Expect(yaml.Unmarshal(raw, &parsed)).To(Succeed())
		receivers := parsed["receivers"].(map[string]any)
		httpCheck := receivers["http_check"].(map[string]any)
		if targetsList, ok := httpCheck["targets"]; ok && targetsList != nil {
			Expect(targetsList.([]any)).To(BeEmpty())
		}
	})

	It("dedupes by host:port keeping the lowest ApiInstance ID", func() {
		path := filepath.Join(GinkgoT().TempDir(), "collector.yaml")
		w, err := otelconfig.NewConfigWriter(otelconfig.ConfigWriterConfig{
			Path:     path,
			Debounce: time.Hour,
			Logger:   zap.NewNop().Sugar(),
		})
		Expect(err).ToNot(HaveOccurred())

		low := uuid.MustParse("00000000-0000-4000-8000-000000000001")
		high := uuid.MustParse("ffffffff-0000-4000-8000-000000000002")
		w.Upsert(targets.ProbeTarget{ApiInstanceID: high, URL: "https://api.example.com:443/a", DedupeKey: "api.example.com:443"})
		w.Upsert(targets.ProbeTarget{ApiInstanceID: low, URL: "https://api.example.com:443/b", DedupeKey: "api.example.com:443"})
		Expect(w.Flush()).To(Succeed())

		raw, err := os.ReadFile(path)
		Expect(err).ToNot(HaveOccurred())
		var parsed map[string]any
		Expect(yaml.Unmarshal(raw, &parsed)).To(Succeed())
		exporters := parsed["exporters"].(map[string]any)
		emeland := exporters["emeland"].(map[string]any)
		mapping := emeland["endpoint_mapping"].(map[string]any)
		Expect(mapping).To(HaveLen(1))
		Expect(mapping["https://api.example.com:443/b"]).To(Equal(low.String()))
	})
})
