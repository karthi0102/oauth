package middleware

import (
	"log"
	"net/http"
	"time"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Logging is a middleware that logs HTTP requests and their duration.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{w, http.StatusOK}

		next.ServeHTTP(lrw, r)

		log.Printf("%s %s %s %d %s", r.RemoteAddr, r.Method, r.URL.Path, lrw.statusCode, time.Since(start))
	})
}
