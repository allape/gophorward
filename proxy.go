package gophorward

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type HttpConnectTunnelProxy struct {
	serverURL *url.URL

	CaCertPool *x509.CertPool
}

// ServeHTTP
//
// curl -v -x "proxy address" https://duckduckgo.com
//
// > CONNECT duckduckgo.com:443 HTTP/1.1
// > Host: duckduckgo.com:443
// > User-Agent: curl/8.7.1
// > Proxy-Connection: Keep-Alive
// >
// < HTTP/1.1 200 Connection established
// <
func (h *HttpConnectTunnelProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	hj, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "not supported", http.StatusInternalServerError)
		return
	}

	cc, _, err := hj.Hijack()
	if err != nil {
		http.Error(writer, "server error", http.StatusInternalServerError)
		return
	}

	shouldCloseNow := false

	tcpConn, err := net.Dial("tcp", h.serverURL.Host)
	if err != nil {
		http.Error(writer, "proxy connect error", http.StatusServiceUnavailable)
		return
	}
	defer func() {
		if shouldCloseNow {
			_ = tcpConn.Close()
		}
	}()

	var tlsConn *tls.Conn
	if h.serverURL.Scheme == "https" {
		tlsConn = tls.Client(tcpConn, &tls.Config{
			ServerName: h.serverURL.Hostname(),
			RootCAs:    h.CaCertPool,
		})
		defer func() {
			if shouldCloseNow {
				_ = tlsConn.Close()
			}
		}()
		if err := tlsConn.Handshake(); err != nil {
			shouldCloseNow = true
			http.Error(writer, "proxy tls error", http.StatusInternalServerError)
			return
		}
	}

	var sb strings.Builder
	for name, values := range request.Header {
		for _, value := range values {
			sb.WriteString(name + ": " + value + "\r\n")
		}
	}

	_, err = tcpConn.Write([]byte(fmt.Sprintf(
		"CONNECT %s %s\r\n%s\r\n",
		request.RequestURI,
		request.Proto,
		sb.String(),
	)))
	if err != nil {
		shouldCloseNow = true
		http.Error(writer, "proxy write error", http.StatusServiceUnavailable)
		return
	}

	sc := tcpConn
	if tlsConn != nil {
		sc = tlsConn
	}

	closeAll := func() {
		_ = cc.Close()
		if tlsConn != nil {
			_ = tlsConn.Close()
		}
		_ = tcpConn.Close()
	}

	go func() {
		defer closeAll()
		_, _ = io.Copy(sc, cc)
	}()
	go func() {
		defer closeAll()
		_, _ = io.Copy(cc, sc)
	}()
}

func NewHttpConnectTunnelProxy(serverURL *url.URL) *HttpConnectTunnelProxy {
	return &HttpConnectTunnelProxy{
		serverURL: serverURL,
	}
}
