package log

import (
	"os"

	uutil "github.com/yomaytk/go_ltrace/util"
	"go.uber.org/zap"
)

var (
	Logger *zap.SugaredLogger
	Config zap.Config
)

const (
	LOG_PATH = "./cache/go_ltrace.log"
)

func InitLogger() error {

	// remove if log file exist (for debug)
	if _, err := os.Stat(LOG_PATH); err == nil {
		err = os.Remove(LOG_PATH)
		uutil.ErrFatal(err)
	} else {
		uutil.ErrFatal(err)
	}

	Config = zap.NewProductionConfig()
	Config.OutputPaths = []string{LOG_PATH}
	logger, err := Config.Build()
	Logger = logger.Sugar()
	uutil.ErrFatal(err)
	return nil
}
