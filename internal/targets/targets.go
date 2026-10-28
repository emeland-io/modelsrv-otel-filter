// Package targets derives OTel http_check probe destinations from ApiInstance
// certificate annotations.
package targets

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	ann "emeland.io/modelsrv-otel-filter/internal/annotations"
	"github.com/google/uuid"
	"go.emeland.io/modelsrv/pkg/model/api"
)

// ProbeTarget describes a synthetic HTTPS probe destination derived from an
// ApiInstance carrying [ann.HTTPSEndpoint].
type ProbeTarget struct {
	ApiInstanceID uuid.UUID
	DisplayName   string
	URL           string
	DedupeKey     string // host:port
}

// TargetFromApiInstance derives a probe target from the certificate HTTPS
// endpoint annotation. When the annotation is missing, the instance is skipped
// (ok == false, err == nil). Invalid values return an error.
func TargetFromApiInstance(ai api.ApiInstance) (ProbeTarget, bool, error) {
	raw := ai.GetAnnotations().GetValue(ann.HTTPSEndpoint)
	if raw == "" {
		return ProbeTarget{}, false, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ProbeTarget{}, false, fmt.Errorf("parse %s: %w", ann.HTTPSEndpoint, err)
	}
	if u.Scheme != "https" {
		return ProbeTarget{}, false, fmt.Errorf("%s must use https scheme, got %q", ann.HTTPSEndpoint, u.Scheme)
	}
	if u.Host == "" {
		return ProbeTarget{}, false, fmt.Errorf("%s missing host", ann.HTTPSEndpoint)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if host == "" {
		return ProbeTarget{}, false, fmt.Errorf("%s missing host", ann.HTTPSEndpoint)
	}

	// Normalize so endpoint_mapping keys match httpcheck's http.url attribute.
	normalized := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, port),
		Path:   normalizePath(u.Path),
	}).String()

	return ProbeTarget{
		ApiInstanceID: ai.GetInstanceId(),
		DisplayName:   ai.GetDisplayName(),
		URL:           normalized,
		DedupeKey:     net.JoinHostPort(host, port),
	}, true, nil
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}
