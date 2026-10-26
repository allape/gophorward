package gophorward

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	CARootCrt        = "cert/root_ca.crt"
	LocalhostCertCrt = "cert/localhost.crt"
	LocalhostCertKey = "cert/localhost.key"
)

// newTestCert
//
// Cert Tool: https://github.com/smallstep/cli
//
// mkdir -p LocalhostCertCrt && cd LocalhostCertCrt
//
// # with password 1
// step certificate create --profile root-ca "Example Root CA" root_ca.crt root_ca.key
//
// # with password 2
//
//	step certificate create "Example Intermediate CA 1" \
//	   intermediate_ca.crt intermediate_ca.key \
//	   --profile intermediate-ca --ca ./root_ca.crt --ca-key ./root_ca.key
//
// # with password 3
//
//	step certificate create localhost localhost.crt localhost.key \
//	   --profile leaf --not-after=8760h \
//	   --no-password --insecure \
//	   --ca ./intermediate_ca.crt --ca-key ./intermediate_ca.key --bundle
func newTestCert() (*tls.Certificate, error) {
	stat, err := os.Stat(LocalhostCertCrt)
	if err != nil {
		return nil, fmt.Errorf("could not stat certificate: %w", err)
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("cert %s is a directory", LocalhostCertCrt)
	}

	stat, err = os.Stat(LocalhostCertKey)
	if err != nil {
		return nil, fmt.Errorf("could not stat private key: %w", err)
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("pkey %s is a directory", LocalhostCertKey)
	}

	certPEM, err := os.ReadFile(LocalhostCertCrt)
	if err != nil {
		return nil, fmt.Errorf("could not read certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(LocalhostCertKey)
	if err != nil {
		return nil, fmt.Errorf("could not read private key: %w", err)
	}

	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate: %w", err)
	}

	return &c, nil
}

func newCAPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	caCert, err := os.ReadFile(CARootCrt)
	if err != nil {
		return nil, err
	}
	pool.AppendCertsFromPEM(caCert)

	return pool, nil
}

func newEchoServer(t *testing.T) (*http.Server, error) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/echo":
			writer.WriteHeader(http.StatusOK)

			_, err := writer.Write([]byte(fmt.Sprintf("%s %s\n\n", request.Method, request.URL.Path)))
			if err != nil {
				t.Fatalf("could not write to response: %v", err)
			}

			for k, v := range request.Header {
				for _, vv := range v {
					_, err := writer.Write([]byte(fmt.Sprintf("%s:%s\n", k, vv)))
					if err != nil {
						t.Fatalf("could not write header: %v", err)
					}
				}
			}
		case "/redirect":
			query := request.URL.Query()
			target := query.Get("target")
			codeStr := query.Get("code")
			code, err := strconv.Atoi(codeStr)
			if err != nil {
				http.Error(writer, fmt.Sprintf("could not parse code: %s", codeStr), http.StatusBadRequest)
				return
			}
			http.Redirect(writer, request, target, code)
		default:
			http.NotFound(writer, request)
		}
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}

	return server, nil
}

func getEcho(client *http.Client, u string, headers ...http.Header) (method, uri string, responseHeader, echoReceivedHeader http.Header, err error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return
	}
	for _, h := range headers {
		for k, vv := range h {
			for _, v := range vv {
				req.Header.Add(k, v)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Fatalf("failed to close response body: %s", err)
		}
	}()

	responseHeader = resp.Header

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	content := string(body)

	lines := strings.Split(content, "\n")
	if len(lines) < 3 {
		err = fmt.Errorf("expected at least 3 lines, got %d", len(lines))
		return
	}

	line1 := strings.Split(lines[0], " ")
	if len(line1) != 2 {
		err = fmt.Errorf("first line should be two parts separated by a space, got %d", len(line1))
		return
	}

	method = line1[0]
	uri = line1[1]

	echoReceivedHeader = make(http.Header)
	for _, line := range lines[2:] {
		before, after, ok := strings.Cut(line, ":")
		if !ok {
			echoReceivedHeader.Add(strings.TrimSpace(line), "")
		} else {
			echoReceivedHeader.Add(strings.TrimSpace(before), strings.TrimSpace(after))
		}
	}
	return
}

func TestGophorward(t *testing.T) {
	localhost, err := url.Parse("http://localhost:8080")

	cert, err := newTestCert()
	if err != nil {
		t.Fatalf("could not create test cert: %v", err)
	}

	pool, err := newCAPool()
	if err != nil {
		t.Fatalf("could not create CA pool: %v", err)
	}

	server, err := NewGophorward(":80", ":443", []RouteConfig{
		{
			Name:                 "public:echo",
			Nonce:                "public:echo",
			Priority:             1000,
			Hostname:             "localhost",
			URIPrefix:            "/public",
			AllowPublicAccess:    true,
			StripURIPrefix:       true,
			AccessLimitPerMinute: 10,
			SetHost:              false,
			EnableCompression:    true,
			Certificate:          cert,
			ForwardTo:            localhost,

			UpHeaders: http.Header{
				"X-Up-Header-1": []string{"UpHeader.1"},
			},
			DownHeaders: http.Header{
				"X-Down-Header-1": []string{"DownHeader.1"},
			},
		},
		{
			Name:                 "private:echo",
			Nonce:                "private:echo",
			Priority:             999,
			Hostname:             "localhost",
			URIPrefix:            "/private",
			AllowPublicAccess:    false,
			StripURIPrefix:       true,
			AccessLimitPerMinute: 0,
			SetHost:              false,
			EnableCompression:    true,
			Certificate:          cert,
			ForwardTo:            localhost,
		},
	}, []Session{
		{
			Token: "1234567890",
			AllowedRoutes: []RouteName{
				"private:echo",
			},
			ExpireAt: time.Now().Add(time.Hour * 999_999),
			UserID:   "johndoe",
			UserName: "John Doe",
		},
	})
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
		return
	}
	defer func() {
		err := server.Shutdown(context.Background())
		if err != nil {
			t.Fatalf("failed to shutdown server: %s", err)
		}
	}()

	server.RedirectURLFor401, err = url.Parse("https://localhost/public/auth/ui/login")
	if err != nil {
		t.Fatalf("could not create redirect URL: %v", err)
	}

	go func() {
		err = server.Serve()
		if err != nil {
			log.Printf("failed to start server: %s", err)
		}
	}()

	echoServer, err := newEchoServer(t)
	if err != nil {
		t.Fatalf("failed to start echo server: %s", err)
	}
	defer func() {
		err := echoServer.Shutdown(context.Background())
		if err != nil {
			t.Fatalf("failed to shutdown echo server: %s", err)
		}
	}()
	go func() {
		_ = echoServer.ListenAndServe()
	}()

	for i := 3; i > 0; i-- {
		t.Logf("%d...", i)
		time.Sleep(1 * time.Second)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	t.Run("test public echo server", func(t *testing.T) {
		method, uri, responseHeader, echoReceivedHeader, err := getEcho(client, "https://localhost/public/echo")
		if err != nil {
			t.Fatalf("failed to get echo: %s", err)
		}
		if method != http.MethodGet {
			t.Fatalf("expected %s request, got %s", http.MethodGet, method)
		}
		if uri != "/echo" {
			t.Fatalf("expected /echo request, got %s", uri)
		}
		if responseHeader.Get("X-Up-Header-1") != "UpHeader.1" {
			t.Fatalf("expected UpHeader.1, got %s", responseHeader.Get("X-Up-Header-1"))
		}
		if echoReceivedHeader.Get("X-Down-Header-1") != "DownHeader.1" {
			t.Fatalf("expected DownHeader.1, got %s", echoReceivedHeader.Get("X-Down-Header-1"))
		}
		if echoReceivedHeader.Get(HeaderRouteNonce) != "public:echo" {
			t.Fatalf("expected public:echo, got %s", echoReceivedHeader.Get(HeaderRouteNonce))
		}
		if echoReceivedHeader.Get(HeaderUserID) != "" {
			t.Fatalf("expected empty string, got %s", echoReceivedHeader.Get(HeaderUserID))
		}
		if echoReceivedHeader.Get(HeaderUserName) != "" {
			t.Fatalf("expected empty string, got %s", echoReceivedHeader.Get(HeaderUserName))
		}
		if strings.Contains(echoReceivedHeader.Get("Cookie"), AuthorizationKey) {
			t.Fatalf("expected not to contain 'AuthorizationKey', got %s", echoReceivedHeader.Get("Cookie"))
		}
		if echoReceivedHeader.Get(AuthorizationKey) != "" {
			t.Fatalf("expected empty string, got %s", echoReceivedHeader.Get(AuthorizationKey))
		}
	})

	t.Run("test private echo server but no auth", func(t *testing.T) {
		resp, err := client.Get("https://localhost/private/echo")
		if err != nil {
			t.Fatalf("failed to get echo: %s", err)
		}
		defer func() {
			err := resp.Body.Close()
			if err != nil {
				t.Fatalf("failed to close response body: %s", err)
			}
		}()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("expected status code %d, got %d", http.StatusFound, resp.StatusCode)
		}

		location := server.RedirectURLFor401.String() + "?" + QueryNextURLName + "=" + url.QueryEscape("https://localhost/private/echo")
		if resp.Header.Get("Location") != location {
			t.Fatalf("expected %s, got %s", location, resp.Header.Get("Location"))
		}
	})

	t.Run("test private echo server with auth", func(t *testing.T) {
		method, uri, responseHeader, echoReceivedHeader, err := getEcho(client, "https://localhost/private/echo", http.Header{
			AuthorizationKey: []string{"1234567890"},
		})
		if err != nil {
			t.Fatalf("failed to get echo: %s", err)
		}
		if method != http.MethodGet {
			t.Fatalf("expected %s request, got %s", http.MethodGet, method)
		}
		if uri != "/echo" {
			t.Fatalf("expected /echo request, got %s", uri)
		}
		if responseHeader.Get("X-Up-Header-1") != "" {
			t.Fatalf("expected empty string, got %s", responseHeader.Get("X-Up-Header-1"))
		}
		if echoReceivedHeader.Get("X-Down-Header-1") != "" {
			t.Fatalf("expected empty string, got %s", echoReceivedHeader.Get("X-Down-Header-1"))
		}
		if echoReceivedHeader.Get(HeaderRouteNonce) != "private:echo" {
			t.Fatalf("expected private:echo, got %s", echoReceivedHeader.Get(HeaderRouteNonce))
		}
		if echoReceivedHeader.Get(HeaderUserID) != "johndoe" {
			t.Fatalf("expected johndoe, got %s", echoReceivedHeader.Get(HeaderUserID))
		}
		if echoReceivedHeader.Get(HeaderUserName) != "John Doe" {
			t.Fatalf("expected John Doe, got %s", echoReceivedHeader.Get(HeaderUserName))
		}
		if echoReceivedHeader.Get(AuthorizationKey) != "" {
			t.Fatalf("expected empty string, got %s", echoReceivedHeader.Get(AuthorizationKey))
		}
	})
}
