package memcache

import (
	"time"

	"github.com/dgraph-io/ristretto/v2"
)

// Options is a functional option type for configuring memCache
type Options func(*options)

// options holds the configuration options for memCache
type options struct {
	numCounters            int64
	maxCost                int64
	metrics                bool
	ttl                    time.Duration
	ttlTickerDurationInSec int64
}

// defaultOptions returns the default options for memCache
func defaultOptions() *options {
	return &options{
		numCounters:            1e7,
		maxCost:                1e6,
		metrics:                false,
		ttl:                    0 * time.Second,
		ttlTickerDurationInSec: 5,
	}
}

// See https://github.com/hypermodeinc/ristretto/blob/main/cache.go#L81-L95
// TL;DR : This is recommended to set to 10x the number of items you expect to keep in the cache when full.
func WithNumCounters(numCounters int64) Options {
	return func(opts *options) {
		opts.numCounters = numCounters
	}
}

// See https://github.com/hypermodeinc/ristretto/blob/main/cache.go#L97-L112
// We assume all entry are of cost 1 to simplify things.
func WithMaxCost(maxCost int64) Options {
	return func(opts *options) {
		opts.maxCost = maxCost
	}
}

// See https://github.com/hypermodeinc/ristretto/blob/main/cache.go#L124-L127
func WithMetrics(metrics bool) Options {
	return func(opts *options) {
		opts.metrics = metrics
	}
}

// WithTtl sets the expiry time for each value entry of the cache.
func WithTtl(ttl time.Duration) Options {
	return func(opts *options) {
		opts.ttl = ttl
	}
}

// See https://github.com/hypermodeinc/ristretto/blob/main/cache.go#L181
// TtlTickerDurationInSec sets the value of time ticker for cleanup keys on TTL expiry.
func WithTtlTickerDurationInSec(ttlTickerDurationInSec int64) Options {
	return func(opts *options) {
		opts.ttlTickerDurationInSec = ttlTickerDurationInSec
	}
}

// Cache is a generic interface for caching operations
type Cache[V any] interface {
	Get(key string) (V, bool)
	Set(key string, value V) bool
}

// memCache is a generic wrapper around ristretto.Cache
type memCache[V any] struct {
	cache *ristretto.Cache[string, V]
	opts  *options
}

// New creates a new memory cache with the specified TTL
func New[V any](opts ...Options) (Cache[V], error) {
	defaultOpts := defaultOptions()
	for _, opt := range opts {
		opt(defaultOpts)
	}

	c, err := ristretto.NewCache(&ristretto.Config[string, V]{
		NumCounters:            defaultOpts.numCounters,
		MaxCost:                defaultOpts.maxCost,
		BufferItems:            64,
		Metrics:                defaultOpts.metrics,
		TtlTickerDurationInSec: defaultOpts.ttlTickerDurationInSec,
	})
	if err != nil {
		return nil, err
	}

	return &memCache[V]{cache: c, opts: defaultOpts}, nil
}

// Get retrieves a value from the cache by key. It returns the value and a boolean indicating if the key was found.
func (cache *memCache[V]) Get(key string) (V, bool) {
	return cache.cache.Get(key)
}

// Set adds a value to the cache with a specified key. It returns true if the value was successfully set, false otherwise.
func (cache *memCache[V]) Set(key string, value V) bool {
	result := cache.cache.SetWithTTL(key, value, 1, cache.opts.ttl)
	cache.cache.Wait()
	return result
}
