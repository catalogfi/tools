package tools

import (
	"github.com/catalogfi/tools/pkg/config"
	"github.com/catalogfi/tools/pkg/cryptutil"
	"github.com/catalogfi/tools/pkg/memcache"
)

var NewAES256 = cryptutil.NewAES256

var LoadConfigFromFile = config.LoadFromFile

var NewParser = config.NewParser

func NewMemCache[V any](options ...memcache.Options) (memcache.Cache[V], error) {
	return memcache.New[V](options...)
}
