// Package server wires the otel-cert-filter building block: a modelsrv Backend
// with the certificate event filter, OTel config writer, and upstream registration.
package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"emeland.io/modelsrv-otel-filter/internal/filter"
	"emeland.io/modelsrv-otel-filter/internal/findings"
	"emeland.io/modelsrv-otel-filter/internal/otelconfig"
	"go.emeland.io/modelsrv/pkg/backend"
	"go.emeland.io/modelsrv/pkg/client"
	"go.emeland.io/modelsrv/pkg/endpoint"
	"go.emeland.io/modelsrv/pkg/model/node"
)

// otelCertFilterNodeTypeID is the stable identity for the "otel-cert-filter" NodeType.
var otelCertFilterNodeTypeID = uuid.MustParse("c4e8a1b2-6f3d-4a90-8e15-7b2d9c0f4a61")

// Config drives listener, upstream registration, and collector config output.
type Config struct {
	ListenAddr         string
	UpstreamAPIBase    string
	CallbackURL        string
	OtelConfigOut      string
	CollectionInterval time.Duration
	ExporterListenAddr string
	ExpiryThreshold    time.Duration
	Debounce           time.Duration
	Subscribers        []string
	Logger             *zap.SugaredLogger
}

// Server is a running otel-cert-filter instance.
type Server struct {
	backend      backend.Backend
	configWriter *otelconfig.ConfigWriter
	nodeID       uuid.UUID
	log          *zap.SugaredLogger
	cancel       context.CancelFunc
}

// Run starts the filter and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	srv, err := Start(ctx, cfg)
	if err != nil {
		return err
	}
	defer srv.Close()

	<-ctx.Done()
	return ctx.Err()
}

// Start constructs and starts the filter server. The caller must Close it.
func Start(ctx context.Context, cfg Config) (*Server, error) {
	log := cfg.Logger
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("listen address required")
	}
	if cfg.UpstreamAPIBase == "" {
		return nil, fmt.Errorf("upstream API base URL required")
	}
	if cfg.OtelConfigOut == "" {
		return nil, fmt.Errorf("otel-config-out path required")
	}
	if cfg.Debounce <= 0 {
		cfg.Debounce = 2 * time.Second
	}
	if cfg.CollectionInterval <= 0 {
		cfg.CollectionInterval = 5 * time.Minute
	}
	if cfg.ExporterListenAddr == "" {
		cfg.ExporterListenAddr = "0.0.0.0:24200"
	}
	if cfg.ExpiryThreshold <= 0 {
		cfg.ExpiryThreshold = 30 * 24 * time.Hour
	}

	b, err := backend.New()
	if err != nil {
		return nil, fmt.Errorf("creating backend: %w", err)
	}

	callback := cfg.CallbackURL
	if callback == "" {
		var derr error
		callback, derr = routableCallback(cfg.ListenAddr)
		if derr != nil {
			return nil, derr
		}
	}

	writer, err := otelconfig.NewConfigWriter(otelconfig.ConfigWriterConfig{
		Path:     cfg.OtelConfigOut,
		Debounce: cfg.Debounce,
		Logger:   log,
		Opts: otelconfig.CollectorConfigOptions{
			CollectionInterval: cfg.CollectionInterval,
			ListenAddr:         cfg.ExporterListenAddr,
			Subscribers:        []string{callback},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("otel config writer: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	go writer.Run(runCtx)

	reconciler := findings.NewReconciler(cfg.ExpiryThreshold, log)
	findings.EnsureFindingTypes(b.GetModel(), log)

	b.GetChain().RegisterFilter(filter.New(filter.Config{
		Writer:     writer,
		Reconciler: reconciler,
		Logger:     log,
	}))

	nt := node.NewNodeType(otelCertFilterNodeTypeID)
	nt.SetDisplayName("otel-cert-filter")
	if err := b.GetModel().AddNodeType(nt); err != nil {
		cancel()
		return nil, fmt.Errorf("register node type: %w", err)
	}

	nodeID := uuid.New()
	n := node.NewNode(nodeID)
	n.SetDisplayName("otel-cert-filter")
	n.SetNodeTypeByRef(nt)
	if err := b.GetModel().AddNode(n); err != nil {
		cancel()
		return nil, fmt.Errorf("register node: %w", err)
	}

	for _, s := range cfg.Subscribers {
		if err := b.GetEventManager().AddSubscriber(s); err != nil {
			cancel()
			return nil, fmt.Errorf("add subscriber %q: %w", s, err)
		}
	}

	if err := endpoint.StartWebListener(b.GetModel(), b.GetEventManager(), cfg.ListenAddr, endpoint.WebListenerOptions{}); err != nil {
		cancel()
		return nil, fmt.Errorf("web listener: %w", err)
	}

	upstream, err := client.NewModelSrvClient(cfg.UpstreamAPIBase)
	if err != nil {
		cancel()
		endpoint.StopWebListener()
		return nil, fmt.Errorf("upstream client: %w", err)
	}
	if err := upstream.Register(callback); err != nil {
		cancel()
		endpoint.StopWebListener()
		return nil, fmt.Errorf("register with upstream: %w", err)
	}

	log.Infow("otel-cert-filter started",
		"listen", cfg.ListenAddr,
		"upstream", cfg.UpstreamAPIBase,
		"callback", callback,
		"otelConfigOut", cfg.OtelConfigOut,
		"expiryThreshold", cfg.ExpiryThreshold,
	)

	return &Server{
		backend:      b,
		configWriter: writer,
		nodeID:       nodeID,
		log:          log,
		cancel:       cancel,
	}, nil
}

// Backend returns the underlying modelsrv backend.
func (s *Server) Backend() backend.Backend {
	return s.backend
}

// Addr returns the web listener address.
func (s *Server) Addr() net.Addr {
	return endpoint.WebListenerAddr()
}

// Close shuts down the filter.
func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.configWriter != nil {
		s.configWriter.Wait()
	}
	if s.backend != nil {
		if err := s.backend.GetModel().DeleteNodeById(s.nodeID); err != nil {
			s.log.Warnw("failed to delete node on shutdown", "nodeId", s.nodeID, "error", err)
		}
	}
	endpoint.StopWebListener()
	return nil
}

// routableCallback derives the upstream callback URL from listenAddr, replacing
// a wildcard host with localhost so the URL is always routable.
func routableCallback(listenAddr string) (string, error) {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", fmt.Errorf("invalid listen address %q: %w", listenAddr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return fmt.Sprintf("http://%s:%s/api", host, port), nil
}
