package memcache_test

import (
	"time"

	"github.com/catalogfi/tools/pkg/memcache"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("memCache", func() {
	var cache memcache.Cache[string]
	var err error

	BeforeEach(func() {
		cache, err = memcache.New[string](memcache.WithTtl(5 * time.Second))
		Expect(err).Should(BeNil())
	})

	Context("when setting and getting a value", func() {
		It("should store and retrieve the value", func() {
			result := cache.Set("foo", "bar")
			Expect(result).To(BeTrue())

			value, found := cache.Get("foo")
			Expect(found).To(BeTrue())
			Expect(value).To(Equal("bar"))
		})
	})

	Context("when the TTL expires", func() {
		It("should not retrieve the value after expiration", func() {
			result := cache.Set("foo", "bar")
			Expect(result).To(BeTrue())

			time.Sleep(6 * time.Second)

			_, found := cache.Get("foo")
			Expect(found).To(BeFalse())
		})
	})
})
