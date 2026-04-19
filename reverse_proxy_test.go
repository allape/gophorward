package gophorward

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
)

func TestReverseProxy(t *testing.T) {
	u, err := url.Parse("http://127.0.0.1:5050")
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)

	var wait sync.WaitGroup

	wait.Add(1)
	go func() {
		defer wait.Done()
		err = http.ListenAndServe(":80", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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

	wait.Add(1)
	go func() {
		defer wait.Done()
		err = http.ListenAndServeTLS(":443", "cert/cert.crt", "cert/cert.key", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			//request.Host = u.Hostname() // uncomment this will make `docker push` unable to forward to registry
			proxy.ServeHTTP(writer, request)
		}))
		if err != nil {
			fmt.Println(err)
		}
	}()

	wait.Wait()
}
