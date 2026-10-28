// modelsrv-otel-filter is an EmELand Filter that builds an OpenTelemetry
// http_check collector config from ApiInstance certificate.https-endpoint
// annotations, merges probe observations from modelsrv-otel-exporter, and
// authors certificate Findings when remaining validity is below threshold.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"emeland.io/modelsrv-otel-filter/internal/server"
)

func main() {
	var (
		listen             = flag.String("listen", envOrDefault("LISTEN", "localhost:8080"), "TCP address for this filter (host:port)")
		upstream           = flag.String("upstream", envOrDefault("UPSTREAM", ""), "Upstream modelsrv API base URL including /api (required)")
		callbackURL        = flag.String("callback-url", envOrDefault("CALLBACK_URL", ""), "Public callback URL upstream uses to reach this filter's /api")
		otelConfigOut      = flag.String("otel-config-out", envOrDefault("OTEL_CONFIG_OUT", ""), "Path to write the OTel collector config (required)")
		collectionInterval = flag.Duration("collection-interval", envDurationOrDefault("COLLECTION_INTERVAL", 5*time.Minute), "collection_interval for the http_check receiver")
		exporterListen     = flag.String("exporter-listen", envOrDefault("EXPORTER_LISTEN", "0.0.0.0:24200"), "listen_addr for the emeland exporter in generated config")
		expiryThreshold    = flag.Duration("expiry-threshold", envDurationOrDefault("EXPIRY_THRESHOLD", 30*24*time.Hour), "Raise CertificateExpiringSoon when remaining validity is at or below this")
		debounce           = flag.Duration("debounce", envDurationOrDefault("DEBOUNCE", 2*time.Second), "Debounce window before rewriting collector config")
		subscribersFlag    = flag.String("subscribers", envOrDefault("SUBSCRIBERS", ""), "Comma-separated downstream modelsrv URLs")
	)
	flag.Parse()

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "missing required -upstream")
		flag.Usage()
		os.Exit(2)
	}
	if *otelConfigOut == "" {
		fmt.Fprintln(os.Stderr, "missing required -otel-config-out")
		flag.Usage()
		os.Exit(2)
	}

	logCfg := zap.NewDevelopmentConfig()
	logCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	log, err := logCfg.Build(zap.AddStacktrace(zap.ErrorLevel))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	slog := log.Sugar()
	defer func() { _ = log.Sync() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, server.Config{
		ListenAddr:         *listen,
		UpstreamAPIBase:    *upstream,
		CallbackURL:        *callbackURL,
		OtelConfigOut:      *otelConfigOut,
		CollectionInterval: *collectionInterval,
		ExporterListenAddr: *exporterListen,
		ExpiryThreshold:    *expiryThreshold,
		Debounce:           *debounce,
		Subscribers:        splitCSV(*subscribersFlag),
		Logger:             slog,
	}); err != nil && ctx.Err() == nil {
		slog.Fatalw("filter exited with error", "error", err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
