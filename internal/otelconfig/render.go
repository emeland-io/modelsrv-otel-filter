package otelconfig

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"emeland.io/modelsrv-otel-filter/internal/targets"
	"gopkg.in/yaml.v3"
)

const defaultCollectionInterval = 5 * time.Minute

type httpCheckTarget struct {
	Method   string `yaml:"method"`
	Endpoint string `yaml:"endpoint"`
}

type httpCheckMetric struct {
	Enabled bool `yaml:"enabled"`
}

type httpCheckReceiver struct {
	CollectionInterval string                     `yaml:"collection_interval"`
	Metrics            map[string]httpCheckMetric `yaml:"metrics"`
	Targets            []httpCheckTarget          `yaml:"targets"`
}

// CollectorConfigOptions controls the output of [RenderCollectorConfig].
type CollectorConfigOptions struct {
	// CollectionInterval for the http_check receiver. Defaults to 5m.
	CollectionInterval time.Duration
	// ListenAddr for the emeland exporter's modelsrv HTTP API.
	ListenAddr string
	// Subscribers is a list of downstream modelsrv URLs (typically this filter).
	Subscribers []string
}

type collectorConfig struct {
	Receivers map[string]httpCheckReceiver `yaml:"receivers"`
	Exporters map[string]emelandExporter   `yaml:"exporters"`
	Service   collectorService             `yaml:"service"`
}

type emelandExporter struct {
	ListenAddr      string            `yaml:"listen_addr"`
	Subscribers     []string          `yaml:"subscribers,omitempty"`
	EndpointMapping map[string]string `yaml:"endpoint_mapping"`
}

type collectorService struct {
	Pipelines map[string]collectorPipeline `yaml:"pipelines"`
}

type collectorPipeline struct {
	Receivers []string `yaml:"receivers"`
	Exporters []string `yaml:"exporters"`
}

// RenderCollectorConfig builds a complete OTel Collector config for the
// modelsrv-otel-exporter binary. Expiry threshold is owned by the filter and
// is not written into this file.
func RenderCollectorConfig(probeTargets []targets.ProbeTarget, opts CollectorConfigOptions) ([]byte, error) {
	if opts.CollectionInterval <= 0 {
		opts.CollectionInterval = defaultCollectionInterval
	}
	if opts.ListenAddr == "" {
		opts.ListenAddr = "0.0.0.0:24200"
	}

	sorted := make([]targets.ProbeTarget, len(probeTargets))
	copy(sorted, probeTargets)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].URL < sorted[j].URL
	})

	outTargets := make([]httpCheckTarget, 0, len(sorted))
	endpointMapping := make(map[string]string, len(sorted))
	for _, t := range sorted {
		outTargets = append(outTargets, httpCheckTarget{
			Method:   "GET",
			Endpoint: t.URL,
		})
		endpointMapping[t.URL] = t.ApiInstanceID.String()
	}

	cfg := collectorConfig{
		Receivers: map[string]httpCheckReceiver{
			"http_check": {
				CollectionInterval: formatDuration(opts.CollectionInterval),
				Metrics: map[string]httpCheckMetric{
					"httpcheck.tls.cert_remaining": {Enabled: true},
				},
				Targets: outTargets,
			},
		},
		Exporters: map[string]emelandExporter{
			"emeland": {
				ListenAddr:      opts.ListenAddr,
				Subscribers:     opts.Subscribers,
				EndpointMapping: endpointMapping,
			},
		},
		Service: collectorService{
			Pipelines: map[string]collectorPipeline{
				"metrics": {
					Receivers: []string{"http_check"},
					Exporters: []string{"emeland"},
				},
			},
		},
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&cfg); err != nil {
		return nil, fmt.Errorf("marshal collector config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("marshal collector config: %w", err)
	}
	return buf.Bytes(), nil
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return formatDuration(defaultCollectionInterval)
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", d/time.Second)
	}
	return d.String()
}
