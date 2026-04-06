package logger

import (
	"go.uber.org/zap"
)

type Logger struct {
	zap *zap.SugaredLogger
}

func New(cfg interface{}) *Logger {
	z, _ := zap.NewProduction()
	return &Logger{zap: z.Sugar()}
}

func (l *Logger) Info(msg string, args ...interface{}) {
	l.zap.Infow(msg, args...)
}

func (l *Logger) Error(msg string, args ...interface{}) {
	l.zap.Errorw(msg, args...)
}

func (l *Logger) Warn(msg string, args ...interface{}) {
	l.zap.Warnw(msg, args...)
}

func (l *Logger) Debug(msg string, args ...interface{}) {
	l.zap.Debugw(msg, args...)
}
