package gophorward

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

type ContentTypePrefixes []string

func (t ContentTypePrefixes) Match(contentType string) bool {
	for _, prefix := range t {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}

// CommonTextBasedContentTypePrefixes
// common text-based content types
// list based on https://developers.cloudflare.com/speed/optimization/content/brotli/content-compression/#compression-between-cloudflare-and-website-visitors
var CommonTextBasedContentTypePrefixes = ContentTypePrefixes{
	"text/",
	"application/javascript",
	"application/json",
	"image/svg+xml",
	"application/xml",
	"application/wasm",

	"application/atom+xml",
	"application/eot",
	"application/font",
	"application/geo+json",
	"application/graphql+json",
	"application/graphql-response+json",
	"application/ld+json",
	"application/manifest+json",
	"application/opentype",
	"application/otf",
	"application/rss+xml",
	"application/truetype",
	"application/ttf",
	"application/vnd.api+json",
	"application/vnd.ms-fontobject",
	"application/x-httpd-cgi",
	"application/x-javascript",
	"application/x-opentype",
	"application/x-otf",
	"application/x-perl",
	"application/x-protobuf",
	"application/x-ttf",
	"application/xhtml+xml",
	"font/ttf",
	"font/otf",
	"image/vnd.microsoft.icon",
	"image/x-icon",
	"multipart/bag",
	"multipart/mixed",
}

type GzipHttpResponseWriter struct {
	io.Closer
	http.ResponseWriter
	http.Hijacker

	responseWriter http.ResponseWriter
	gzipWriter     *gzip.Writer

	alreadyCompressed bool
	hijacked          bool
}

func (g *GzipHttpResponseWriter) Header() http.Header {
	return g.responseWriter.Header()
}

func (g *GzipHttpResponseWriter) Write(data []byte) (int, error) {
	if g.alreadyCompressed {
		return g.responseWriter.Write(data)
	}
	return g.gzipWriter.Write(data)
}

func (g *GzipHttpResponseWriter) WriteHeader(statusCode int) {
	headers := g.Header()

	g.alreadyCompressed = headers.Get("Content-Encoding") != "" ||
		!CommonTextBasedContentTypePrefixes.Match(headers.Get("Content-Type"))

	if !g.alreadyCompressed {
		headers.Del("Content-Length")
		headers.Set("Content-Encoding", "gzip")
	}

	g.responseWriter.WriteHeader(statusCode)
}

func (g *GzipHttpResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r, ok := g.responseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("non-Hijacker ResponseWriter of GzipHttpResponseWriter")
	}

	g.hijacked = true
	return r.Hijack()
}

func (g *GzipHttpResponseWriter) Close() error {
	if g.alreadyCompressed || g.hijacked {
		return nil
	}
	return g.gzipWriter.Close()
}

func NewGzipHttpResponseWriter(responseWriter http.ResponseWriter) *GzipHttpResponseWriter {
	return &GzipHttpResponseWriter{
		responseWriter: responseWriter,
		gzipWriter:     gzip.NewWriter(responseWriter),
	}
}
