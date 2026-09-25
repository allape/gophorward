package gophorward

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

type Servable interface {
	ServeHTTP(writer http.ResponseWriter, request *http.Request)
}

func serveProxy(t *testing.T, proxy Servable) {
	go func() {
		err := http.ListenAndServe(":80", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if !IsHttps(request) && CanRedirect2Https(request) {
				http.Redirect(writer, request, "https://"+request.Host+request.URL.String(), http.StatusPermanentRedirect)
				return
			}
			proxy.ServeHTTP(writer, request)
		}))
		if err != nil {
			fmt.Println(err)
		}
	}()

	go func() {
		err := http.ListenAndServeTLS(":443", "cert/_.testlan.allape.cc.crt", "cert/_.testlan.allape.cc.key", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			//request.Host = u.Hostname() // uncomment this will make `docker push` unable to forward to registry
			proxy.ServeHTTP(writer, request)
		}))
		if err != nil {
			fmt.Println(err)
		}
	}()

	t.Log("press Ctrl+C to stop")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
}

func TestReverseProxy(t *testing.T) {
	// dufs -p 5050 .
	u, err := url.Parse("http://127.0.0.1:5050")
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)

	serveProxy(t, proxy)
}

func TestReverseProxyForHttpProxyTunnel(t *testing.T) {
	u, err := url.Parse("http://127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	proxy := NewHttpConnectTunnelProxy(u)

	serveProxy(t, proxy)
}
