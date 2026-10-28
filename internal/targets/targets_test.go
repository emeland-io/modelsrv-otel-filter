package targets_test

import (
	"testing"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ann "emeland.io/modelsrv-otel-filter/internal/annotations"
	"emeland.io/modelsrv-otel-filter/internal/targets"
	"go.emeland.io/modelsrv/pkg/model/api"
)

func TestTargets(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Targets Suite")
}

var _ = Describe("TargetFromApiInstance", func() {
	It("skips instances without the https-endpoint annotation", func() {
		ai := api.NewApiInstance(uuid.New())
		_, ok, err := targets.TargetFromApiInstance(ai)
		Expect(err).ToNot(HaveOccurred())
		Expect(ok).To(BeFalse())
	})

	It("parses a full https URL", func() {
		id := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
		ai := api.NewApiInstance(id)
		ai.SetDisplayName("payments")
		ai.GetAnnotations().Add(ann.HTTPSEndpoint, "https://payments.example.com:443/health")

		target, ok, err := targets.TargetFromApiInstance(ai)
		Expect(err).ToNot(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(target.ApiInstanceID).To(Equal(id))
		Expect(target.URL).To(Equal("https://payments.example.com:443/health"))
		Expect(target.DedupeKey).To(Equal("payments.example.com:443"))
	})

	It("defaults port 443 and path /", func() {
		ai := api.NewApiInstance(uuid.New())
		ai.GetAnnotations().Add(ann.HTTPSEndpoint, "https://api.example.com")

		target, ok, err := targets.TargetFromApiInstance(ai)
		Expect(err).ToNot(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(target.URL).To(Equal("https://api.example.com:443/"))
		Expect(target.DedupeKey).To(Equal("api.example.com:443"))
	})

	It("rejects http URLs", func() {
		ai := api.NewApiInstance(uuid.New())
		ai.GetAnnotations().Add(ann.HTTPSEndpoint, "http://api.example.com/health")

		_, ok, err := targets.TargetFromApiInstance(ai)
		Expect(ok).To(BeFalse())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("https"))
	})

	It("rejects unparseable values", func() {
		ai := api.NewApiInstance(uuid.New())
		ai.GetAnnotations().Add(ann.HTTPSEndpoint, "://bad")

		_, ok, err := targets.TargetFromApiInstance(ai)
		Expect(ok).To(BeFalse())
		Expect(err).To(HaveOccurred())
	})
})
