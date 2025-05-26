package gin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/middleware-labs/golang-apm/tracker"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// sourceReader handles reading and caching source files
type sourceReader struct {
	mu    sync.Mutex
	cache map[string][][]byte
}

// StackDetail represents details of a single stack frame
type StackDetail struct {
	FunctionName   string `json:"exception.function_name"`
	File           string `json:"exception.file"`
	Line           int    `json:"exception.line"`
	FunctionBody   string `json:"exception.function_body"`
	IsFileExternal bool   `json:"exception.is_file_external"`
	Language       string `json:"exception.language"`
	StartLine      int    `json:"exception.start_line"`
	EndLine        int    `json:"exception.end_line"`
}

// newSourceReader creates a new source reader instance
func newSourceReader() *sourceReader {
	return &sourceReader{
		cache: make(map[string][][]byte),
	}
}

var globalSourceReader = newSourceReader()

// readContextLines reads lines around a specific line number from a file
func (sr *sourceReader) readContextLines(filename string, line, contextLines int) ([][]byte, int) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	lines, ok := sr.cache[filename]

	if !ok {
		data, err := os.ReadFile(filename)
		if err != nil {
			sr.cache[filename] = nil
			return nil, 0
		}
		lines = bytes.Split(data, []byte{'\n'})
		sr.cache[filename] = lines
	}

	return sr.calculateContextLines(lines, line, contextLines)
}

// calculateContextLines extracts lines around a specific line number
func (sr *sourceReader) calculateContextLines(lines [][]byte, line, contextLines int) ([][]byte, int) {
	// Stacktrace lines are 1-indexed, slices are 0-indexed
	line--

	// contextLine points to a line that caused an issue itself, in relation to returned slice
	contextLine := contextLines

	if lines == nil || line >= len(lines) || line < 0 {
		return nil, 0
	}

	if contextLines < 0 {
		contextLines = 0
		contextLine = 0
	}

	start := line - contextLines
	if start < 0 {
		contextLine += start
		start = 0
	}

	end := line + contextLines + 1
	if end > len(lines) {
		end = len(lines)
	}

	return lines[start:end], contextLine
}

// isInAppFrame determines if a frame is part of the application code
func isInAppFrame(file string) bool {
	// Consider frames outside of Go stdlib and vendor directories as in-app
	if strings.Contains(file, "/go/src/") ||
		strings.Contains(file, "/go/pkg/mod") ||
		strings.Contains(file, "vendor/") ||
		strings.Contains(file, "third_party/") {
		return false
	}
	return true
}

// extractFunctionCode extracts source code around a specific line
// and returns the code, start line, and end line
func extractFunctionCode(file string, line int, contextLines int) (string, int, int) {
	// Always attempt to extract code, even for external files.
	lines, contextLine := globalSourceReader.readContextLines(file, line, contextLines)
	if len(lines) == 0 {
		return "", 0, 0
	}

	var result strings.Builder
	for i, lineBytes := range lines {
		result.Write(lineBytes)
		if i < len(lines)-1 {
			result.WriteString("\n")
		}
	}

	// Calculate start and end line numbers (1-indexed)
	startLine := line - contextLine
	if startLine < 1 {
		startLine = 1
	}
	endLine := startLine + len(lines) - 1

	return result.String(), startLine, endLine
}

// extractStackTrace extracts detailed stack trace information
func extractStackTrace(skip int) ([]StackDetail, string) {
	const maxFrames = 32
	pcs := make([]uintptr, maxFrames)
	n := runtime.Callers(skip, pcs)

	if n == 0 {
		return nil, ""
	}

	frames := runtime.CallersFrames(pcs[:n])
	var stackDetails []StackDetail
	var traceLines []string

	for {
		frame, more := frames.Next()

		// Skip runtime and middleware internals
		if shouldSkipFrame(frame.Function) {
			if !more {
				break
			}
			continue
		}

		functionName := extractFunctionName(frame.Function)
		functionBody, startLine, endLine := extractFunctionCode(frame.File, frame.Line, 5) // 5 lines of context

		stackDetail := StackDetail{
			FunctionName:   functionName,
			File:           frame.File,
			Line:           frame.Line,
			FunctionBody:   functionBody,
			IsFileExternal: !isInAppFrame(frame.File),
			Language:       "go",
			StartLine:      startLine,
			EndLine:        endLine,
		}

		stackDetails = append(stackDetails, stackDetail)

		// Build traditional stack trace line
		traceLine := fmt.Sprintf("  at %s (%s:%d)", functionName, filepath.Base(frame.File), frame.Line)
		traceLines = append(traceLines, traceLine)

		if !more {
			break
		}
	}

	stackTrace := strings.Join(traceLines, "\n")
	return stackDetails, stackTrace
}

// shouldSkipFrame determines if a frame should be skipped in stack traces
func shouldSkipFrame(function string) bool {
	skipPrefixes := []string{
		"runtime.",
		"panic",
		"golang-apm-gin.",
		"go.opentelemetry.io/",
		"github.com/gin-gonic/gin.",
	}

	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(function, prefix) {
			return true
		}
	}

	return false
}

// extractFunctionName extracts clean function name from full qualified name
func extractFunctionName(fullName string) string {
	if fullName == "" {
		return "unknown"
	}

	// Split by last dot to get function name
	parts := strings.Split(fullName, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}

	return fullName
}

func Middleware(config *tracker.Config) gin.HandlerFunc {
	return otelgin.Middleware(config.ServiceName)
}

// EnhancedRecovery returns a Gin middleware that records detailed stack traces on panics
func EnhancedRecovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		// Retrieve current span
		span := trace.SpanFromContext(c.Request.Context())

		// Extract detailed stack information
		stackDetails, stackTrace := extractStackTrace(3) // Skip 3 frames: runtime.Callers, extractStackTrace, CustomRecovery

		// Create error message
		errMsg := fmt.Sprintf("%v", recovered)

		// Serialize stack details to JSON
		stackDetailsJSON, err := json.Marshal(stackDetails)
		if err != nil {
			stackDetailsJSON = []byte("[]") // Fallback to empty array
		}

		// Create exception event attributes
		eventAttrs := []attribute.KeyValue{
			attribute.String("exception.type", "RuntimePanic"),
			attribute.String("exception.message", errMsg),
			attribute.String("exception.stacktrace", fmt.Sprintf("Panic: %s\n%s", errMsg, stackTrace)),
			attribute.Bool("exception.escaped", true),
			attribute.String("exception.stack_details", string(stackDetailsJSON)),
		}

		// Add exception event to span
		span.AddEvent("exception", trace.WithAttributes(eventAttrs...), trace.WithTimestamp(time.Now()))

		// Set span status
		// span.RecordError(fmt.Errorf("%v", recovered))
		span.SetStatus(codes.Error, errMsg)

		// Return error response
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "An unexpected error occurred",
		})
		c.Abort()
	})
}

// CombinedMiddleware combines OpenTelemetry middleware with enhanced panic recovery
func CombinedMiddleware(config *tracker.Config) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Set up panic recovery for the current request BEFORE calling Next()
		defer func() {
			if recovered := recover(); recovered != nil {
				// Get current span
				span := trace.SpanFromContext(c.Request.Context())

				// Extract detailed stack information
				stackDetails, stackTrace := extractStackTrace(3)

				// Create error message
				errMsg := fmt.Sprintf("%v", recovered)

				// Serialize stack details to JSON
				stackDetailsJSON, err := json.Marshal(stackDetails)
				if err != nil {
					stackDetailsJSON = []byte("[]") // Fallback to empty array
				}

				// Create exception event attributes
				eventAttrs := []attribute.KeyValue{
					attribute.String("exception.type", "RuntimePanic"),
					attribute.String("exception.message", errMsg),
					attribute.String("exception.stacktrace", fmt.Sprintf("Panic: %s\n%s", errMsg, stackTrace)),
					attribute.Bool("exception.escaped", true),
					attribute.String("exception.stack_details", string(stackDetailsJSON)),
				}

				// Add exception event to span
				span.AddEvent("exception", trace.WithAttributes(eventAttrs...), trace.WithTimestamp(time.Now()))

				// Set span status
				// span.RecordError(fmt.Errorf("%v", recovered))
				span.SetStatus(codes.Error, errMsg)

				// Return error response
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "Internal Server Error",
					"message": "An unexpected error occurred",
				})
				c.Abort()
			}
		}()

		// Continue with the request - this will process all subsequent middlewares and handlers
		c.Next()
	})
}

// CombinedMiddlewareWithOtel creates a middleware chain with both OpenTelemetry and enhanced recovery
// This should be used instead of CombinedMiddleware for proper middleware chaining
func MiddlewareExtended(config *tracker.Config) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		otelgin.Middleware(config.ServiceName), // OpenTelemetry middleware first
		CombinedMiddleware(config),             // Then our enhanced recovery
	}
}

// CustomRecovery returns a Gin middleware that records stack traces on panics
func CustomRecovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		// Retrieve current span
		span := trace.SpanFromContext(c.Request.Context())
		// Record panic as error with stack trace
		err := fmt.Errorf("%v", recovered)
		span.RecordError(err, trace.WithStackTrace(true))
		span.SetStatus(codes.Error, err.Error())

		// Optionally, write a JSON response
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		// Abort to prevent other handlers
		c.Abort()
	})
}
