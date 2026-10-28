// Package annotations defines well-known emeland.io annotation keys for
// certificate probing of ApiInstance resources.
package annotations

const (
	// HTTPSEndpoint marks an ApiInstance for OTel certificate probing.
	// Value is an absolute https URL (e.g. https://payments.example.com:443/health).
	HTTPSEndpoint = "emeland.io/certificate.https-endpoint"

	// Remaining is seconds until TLS certificate expiry (negative when expired).
	Remaining = "emeland.io/certificate.remaining"

	// NotAfter is the certificate expiry time in RFC3339.
	NotAfter = "emeland.io/certificate.not-after"

	// Issuer is the certificate issuer DN.
	Issuer = "emeland.io/certificate.issuer"

	// CommonName is the certificate subject common name.
	CommonName = "emeland.io/certificate.common-name"

	// SAN is a comma-separated list of subject alternative names.
	SAN = "emeland.io/certificate.san"

	// Error holds the last probe failure message; cleared on success.
	Error = "emeland.io/certificate.error"

	// ProbedAt is the RFC3339 timestamp of the last probe observation.
	ProbedAt = "emeland.io/certificate.probed-at"

	// Source marks an ApiInstance event as an OTel exporter observation.
	// Value is always SourceOTel. Stripped before the merged resource is published.
	Source = "emeland.io/certificate.source"

	// SourceOTel is the only valid value for [Source].
	SourceOTel = "otel"
)

// ObservationKeys are the certificate observation annotations written by the
// exporter and merged onto ApiInstance by the filter.
var ObservationKeys = []string{
	Remaining,
	NotAfter,
	Issuer,
	CommonName,
	SAN,
	Error,
	ProbedAt,
}
