// Package httpx holds shared HTTP middleware and helpers.
package httpx

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/example/rust-go/go-api/internal/auth"
)

type ctxKey int

const requestIDKey ctxKey = iota

func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Middleware: request id, panic recovery, access log, security headers.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 64 {
			id = auth.RandomToken(9)
		}
		w.Header().Set("X-Request-ID", id)
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'")

		rec := &statusRecorder{ResponseWriter: w, status: 200}
		defer func() {
			if p := recover(); p != nil {
				slog.Error("panic", "err", p, "request_id", id, "stack", string(debug.Stack()))
				http.Error(rec, "internal error", http.StatusInternalServerError)
			}
			slog.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
				"ms", time.Since(start).Milliseconds(), "request_id", id)
		}()
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// ClientIP uses the socket address. If you deploy behind a proxy, replace
// this with trusted X-Forwarded-For parsing for your proxy only.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func JSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func Error(w http.ResponseWriter, r *http.Request, code int, msg string) {
	JSON(w, code, map[string]string{"error": msg, "request_id": RequestID(r.Context())})
}

// ErrMsg is the human-readable message of an engine (gRPC) or plain error.
func ErrMsg(err error) string {
	if st, ok := status.FromError(err); ok && st.Message() != "" {
		return st.Message()
	}
	return err.Error()
}

// GRPCStatus maps engine errors to HTTP status codes.
func GRPCStatus(err error) (int, string) {
	st, _ := status.FromError(err)
	switch st.Code() {
	case codes.InvalidArgument:
		return http.StatusBadRequest, st.Message()
	case codes.NotFound:
		return http.StatusNotFound, st.Message()
	case codes.AlreadyExists:
		return http.StatusConflict, st.Message()
	case codes.PermissionDenied:
		return http.StatusForbidden, st.Message()
	case codes.FailedPrecondition:
		return http.StatusConflict, st.Message()
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout, st.Message()
	case codes.Unavailable:
		return http.StatusBadGateway, st.Message()
	case codes.Unauthenticated:
		// Go <-> engine token problem: a server misconfiguration, not the client's fault.
		return http.StatusInternalServerError, "engine authentication failed"
	default:
		return http.StatusBadGateway, st.Message()
	}
}
