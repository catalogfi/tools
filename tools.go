package tools

import (
	"github.com/catalogfi/tools/pkg/config"
	"github.com/catalogfi/tools/pkg/cryptutil"
)

var NewAES256 = cryptutil.NewAES256

var LoadConfigFromFile = config.LoadFromFile

var NewParser = config.NewParser
