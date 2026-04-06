package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	zap *zap.SugaredLogger
}

func New(level string) *Logger {
	lvl := zap.InfoLevel
	if level == "debug" {
		lvl = zap.DebugLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	z, _ := cfg.Build()
	return &Logger{zap: z.Sugar()}
}

func (l *Logger) Info(msg string, args ...interface{})  { l.zap.Infow(msg, args...) }
func (l *Logger) Error(msg string, args ...interface{}) { l.zap.Errorw(msg, args...) }
func (l *Logger) Warn(msg string, args ...interface{})  { l.zap.Warnw(msg, args...) }
func (l *Logger) Debug(msg string, args ...interface{}) { l.zap.Debugw(msg, args...) }
