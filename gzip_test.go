package gophorward

import (
	"net/http"
	"testing"
)

type TestResponseWriter struct {
	http.ResponseWriter
	headers    http.Header
	statusCode int
}

func (t *TestResponseWriter) Header() http.Header {
	if t.headers == nil {
		t.headers = make(http.Header)
	}
	return t.headers
}

func (t *TestResponseWriter) Write(data []byte) (int, error) {
	return len(data), nil
}

func (t *TestResponseWriter) WriteHeader(statusCode int) {
	t.statusCode = statusCode
}

func TestNewGzipHttpResponseWriter(t *testing.T) {
	writer := &TestResponseWriter{}
	gzipw := NewGzipHttpResponseWriter(writer)

	gzipw.Header().Set("Content-Type", "text/html; charset=utf-8")
	gzipw.WriteHeader(http.StatusOK)

	if gzipw.alreadyCompressed {
		t.Fatalf("expected false, got true")
		return
	}

	ce := gzipw.Header().Get("Content-Encoding")
	if ce != "gzip" {
		t.Fatalf("expected gzip, got %s", ce)
		return
	}

	cl := gzipw.Header().Get("Content-Length")
	if cl != "" {
		t.Fatalf("expected empty string, got %s", cl)
		return
	}

	gzipw.Header().Set("Content-Type", "video/mp4")
	gzipw.WriteHeader(http.StatusOK)
	if !gzipw.alreadyCompressed {
		t.Fatalf("expected true, got false")
	}

	gzipw.Header().Set("Content-Type", "image/png")
	gzipw.WriteHeader(http.StatusOK)
	if !gzipw.alreadyCompressed {
		t.Fatalf("expected true, got false")
	}

	gzipw.Header().Set("Content-Encoding", "gzip")
	gzipw.WriteHeader(http.StatusOK)
	if !gzipw.alreadyCompressed {
		t.Fatalf("expected true, got false")
	}
}
