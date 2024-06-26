package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func GetAccessLogWriter(accessLog string) io.Writer {
	return &lumberjack.Logger{
		Filename:   accessLog,
		MaxSize:    100, // megabytes
		MaxBackups: 10,
		MaxAge:     31, //days
		LocalTime:  true,
		Compress:   true, // disabled by default
	}
}

// Flusher is the callback function which flushes any buffered log entries to the underlying writer.
// It is usually called before the gnet process exits.
type Flusher = func() error

var (
	defaultLogger       Logger
	defaultLoggingLevel Level
	defaultFlusher      Flusher
	defaultWriteSyncer  zapcore.WriteSyncer
)

// Level is the alias of zapcore.Level.
type Level = zapcore.Level

const (
	// DebugLevel logs are typically voluminous, and are usually disabled in
	// production.
	DebugLevel = zapcore.DebugLevel
	// InfoLevel is the default logging priority.
	InfoLevel = zapcore.InfoLevel
	// WarnLevel logs are more important than Info, but don't need individual
	// human review.
	WarnLevel = zapcore.WarnLevel
	// ErrorLevel logs are high-priority. If an application is running smoothly,
	// it shouldn't generate any error-level logs.
	ErrorLevel = zapcore.ErrorLevel
	// DPanicLevel logs are particularly important errors. In development the
	// logger panics after writing the message.
	DPanicLevel = zapcore.DPanicLevel
	// PanicLevel logs a message, then panics.
	PanicLevel = zapcore.PanicLevel
	// FatalLevel logs a message, then calls os.Exit(1).
	FatalLevel = zapcore.FatalLevel
)

func init() {
	lvl := os.Getenv("SOCKS5_LOGGING_LEVEL")
	if len(lvl) > 0 {
		loggingLevel, err := strconv.ParseInt(lvl, 10, 8)
		if err != nil {
			panic("invalid SOCKS5_LOGGING_LEVEL, " + err.Error())
		}
		defaultLoggingLevel = Level(loggingLevel)
	}

	// Initializes the inside default logger of gnet.
	fileName := os.Getenv("SOCKS5_LOGGING_FILE")
	if len(fileName) > 0 {
		if !strings.HasSuffix(fileName, ".log") {
			panic(fmt.Sprintf("log file name should ends with a .log, fileName: %s", fileName))
		}
		if os.Getenv("SOCKS5_LOGGING_FILE_APPEND_PID") == "true" {
			pid := os.Getpid()
			fileName = regexp.MustCompile("\\.log$").ReplaceAllString(fileName, fmt.Sprintf("-%d.log", pid))
		}
		fmt.Printf("log file name: %s\n", fileName)
		var err error
		defaultLogger, defaultWriteSyncer, defaultFlusher, err = CreateLoggerAsLocalFile(fileName, defaultLoggingLevel)
		if err != nil {
			panic("invalid SOCKS5_LOGGING_FILE, " + err.Error())
		}
	} else {
		core := zapcore.NewCore(getDevEncoder(), zapcore.Lock(os.Stdout), defaultLoggingLevel)
		zapLogger := zap.New(core,
			zap.AddCallerSkip(1),
			zap.Development(),
			zap.AddCaller(),
			zap.AddStacktrace(ErrorLevel),
			zap.ErrorOutput(zapcore.Lock(os.Stderr)))
		defaultLogger = zapLogger.Sugar()
	}
}

func NewZapLogger(prefix string, logLevel Level) (logger *zap.Logger, flush Flusher) {
	if defaultWriteSyncer != nil {
		levelEnabler := zap.LevelEnablerFunc(func(level Level) bool {
			return level >= logLevel
		})
		encoder := getProdEncoder(prefix)
		core := zapcore.NewCore(encoder, defaultWriteSyncer, levelEnabler)
		zapLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(ErrorLevel))
		logger = zapLogger
		flush = zapLogger.Sync
	} else {
		core := zapcore.NewCore(getDevEncoder(prefix), zapcore.Lock(os.Stdout), logLevel)
		zapLogger := zap.New(core,
			zap.Development(),
			zap.AddCaller(),
			zap.AddStacktrace(ErrorLevel),
			zap.ErrorOutput(zapcore.Lock(os.Stderr)))
		logger = zapLogger
		flush = dummyFlusher
	}
	return
}

func NewLogger(prefix string, logLevel Level, skip int) (Logger, Flusher) {
	zapLogger, flush := NewZapLogger(prefix, logLevel)
	if skip > 0 {
		zapLogger = zapLogger.WithOptions(zap.AddCallerSkip(skip))
	}
	return zapLogger.Sugar(), flush
}

type prefixEncoder struct {
	zapcore.Encoder

	prefix  string
	bufPool buffer.Pool
}

func (e *prefixEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	buf := e.bufPool.Get()

	buf.AppendString(e.prefix)
	buf.AppendString(" ")

	logEntry, err := e.Encoder.EncodeEntry(entry, fields)
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(logEntry.Bytes())
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func getDevEncoder(opts ...string) zapcore.Encoder {
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02T15:04:05.000000000-07:00")
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	prefix := "[socks5]"
	if len(opts) > 0 {
		prefix = opts[0]
	}
	return &prefixEncoder{
		Encoder: zapcore.NewConsoleEncoder(encoderConfig),
		prefix:  prefix,
		bufPool: buffer.NewPool(),
	}
}

func getProdEncoder(opts ...string) zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02T15:04:05.000000000-07:00")
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	prefix := "[socks5]"
	if len(opts) > 0 {
		prefix = opts[0]
	}
	return &prefixEncoder{
		Encoder: zapcore.NewConsoleEncoder(encoderConfig),
		prefix:  prefix,
		bufPool: buffer.NewPool(),
	}
}

// GetDefaultLogger returns the default logger.
func GetDefaultLogger() Logger {
	return defaultLogger
}

// GetDefaultFlusher returns the default flusher.
func GetDefaultFlusher() Flusher {
	return defaultFlusher
}

var setupOnce sync.Once

// SetDefaultLoggerAndFlusher sets the default logger and its flusher.
//
// Note that this function should only be called once at the
// start of the program and not thereafter for the entire runtime,
// otherwise it will only keep the first setup.
func SetDefaultLoggerAndFlusher(logger Logger, flusher Flusher) {
	setupOnce.Do(func() {
		defaultLogger, defaultFlusher = logger, flusher
	})
}

// LogLevel tells what the default logging level is.
func LogLevel() string {
	return defaultLoggingLevel.String()
}

// CreateLoggerAsLocalFile setups the logger by local file path.
func CreateLoggerAsLocalFile(localFilePath string, logLevel Level) (logger Logger, ws zapcore.WriteSyncer, flush func() error, err error) {
	if len(localFilePath) == 0 {
		return nil, nil, nil, errors.New("invalid local logger path")
	}

	// lumberjack.Logger is already safe for concurrent use, so we don't need to lock it.
	lumberJackLogger := &lumberjack.Logger{
		Filename:   localFilePath,
		MaxSize:    100, // megabytes
		MaxBackups: 100,
		MaxAge:     15, // days
	}

	encoder := getProdEncoder()
	ws = zapcore.Lock(zapcore.AddSync(lumberJackLogger))

	levelEnabler := zap.LevelEnablerFunc(func(level Level) bool {
		return level >= logLevel
	})
	core := zapcore.NewCore(encoder, ws, levelEnabler)
	zapLogger := zap.New(core, zap.AddCallerSkip(1), zap.AddCaller(), zap.AddStacktrace(ErrorLevel))
	logger = zapLogger.Sugar()
	flush = zapLogger.Sync
	return
}

// Cleanup does something windup for logger, like closing, flushing, etc.
func Cleanup() {
	if defaultFlusher != nil {
		_ = defaultFlusher()
	}
}

// Error prints err if it's not nil.
func Error(err error) {
	if err != nil {
		defaultLogger.Errorf("error occurs during runtime, %v", err)
	}
}

// Debugf logs messages at DEBUG level.
func Debugf(format string, args ...interface{}) {
	defaultLogger.Debugf(format, args...)
}

// Debug logs messages at DEBUG level.
func Debug(args ...interface{}) {
	defaultLogger.Debug(args...)
}

// Infof logs messages at INFO level.
func Infof(format string, args ...interface{}) {
	defaultLogger.Infof(format, args...)
}

// Info logs messages at INFO level.
func Info(args ...interface{}) {
	defaultLogger.Info(args...)
}

// Warnf logs messages at WARN level.
func Warnf(format string, args ...interface{}) {
	defaultLogger.Warnf(format, args...)
}

// Warn logs messages at WARN level.
func Warn(args ...interface{}) {
	defaultLogger.Warn(args...)
}

// Errorf logs messages at ERROR level.
func Errorf(format string, args ...interface{}) {
	defaultLogger.Errorf(format, args...)
}

// Fatalf logs messages at FATAL level.
func Fatalf(format string, args ...interface{}) {
	defaultLogger.Fatalf(format, args...)
}

// Fatal logs messages at FATAL level.
func Fatal(args ...interface{}) {
	defaultLogger.Fatal(args...)
}

// Logger is used for logging formatted messages.
type Logger interface {
	// Debugf logs messages at DEBUG level.
	Debugf(format string, args ...interface{})
	// Debug logs messages at DEBUG level.
	Debug(args ...interface{})
	// Infof logs messages at INFO level.
	Infof(format string, args ...interface{})
	// Info logs messages at INFO level.
	Info(args ...interface{})
	// Warnf logs messages at WARN level.
	Warnf(format string, args ...interface{})
	// Warn logs messages at WARN level.
	Warn(args ...interface{})
	// Errorf logs messages at ERROR level.
	Errorf(format string, args ...interface{})
	// Error logs messages at ERROR level.
	Error(args ...interface{})
	// Fatalf logs messages at FATAL level.
	Fatalf(format string, args ...interface{})
	// Fatal logs messages at FATAL level.
	Fatal(args ...interface{})
}

func dummyFlusher() error {
	return nil
}
