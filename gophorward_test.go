package gophorward

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestNewGophorward(t *testing.T) {
	dufs, err := dufsConfig()
	if err != nil {
		t.Fatalf("failed to load dufs config: %s", err)
		return
	}

	mqtt, err := mqttConfig()
	if err != nil {
		t.Fatalf("failed to load mqtt config: %s", err)
		return
	}

	dockerRegistry, err := dockerRegistryConfig()
	if err != nil {
		t.Fatalf("failed to load docker registry config: %s", err)
		return
	}

	server, err := NewGophorward(":80", ":443", []RouteConfig{
		*dufs,
		*mqtt,
		*dockerRegistry,
	}, []AuthorizedToken{
		{
			Token: "1234567890",
			AllowedRoutes: []RouteName{
				"dufs",
			},
			ExpireAt: time.Now().Add(time.Hour * 999_999),

			UserID:   "1",
			UserName: "John Doe",
		},
	})
	if err != nil {
		t.Fatalf("failed to create server: %s", err)
		return
	}

	go func() {
		err = server.Serve()
		if err != nil {
			log.Printf("failed to start server: %s", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	err = server.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("failed to shutdown server: %s", err)
		return
	}
}

// dufsConfig
// Common test for http and https, there is no obviously error in this section
func dufsConfig() (*RouteConfig, error) {
	/*
		sudo echo "127.0.0.1 dufs.testlan.allape.cc" >> /etc/hosts

		dufs --port 5050 .

		# test ops
		# open url https://dufs.testlan.allape.cc/
		# run below javascript in Console to apply token in Cookies
		document.cookie = "x-goor-token=1234567890; Max-Age=31536000; Domain=.testlan.allape.cc; Path=/"
	*/
	u, err := url.Parse("http://127.0.0.1:5050")
	if err != nil {
		return nil, fmt.Errorf("failed to parse dufs config: %s", err)
	}

	r := &RouteConfig{
		Name:                 "dufs",
		Priority:             100,
		Hostname:             "dufs.testlan.allape.cc",
		URIPrefix:            "",
		AllowPublicAccess:    false,
		StripURIPrefix:       false,
		AccessLimitPerMinute: 60,
		SetHost:              false,
		EnableCompression:    true,

		ForwardTo: u,
	}

	cert, ok, err := testCert()
	if err != nil {
		log.Printf("failed to load test certificate: %s", err)
	} else if !ok {
		log.Printf("no test certificate loaded")
	} else {
		r.Certificate = cert
	}

	return r, nil
}

// mqttConfig
// http.Hijacker should be handled for WebSocket
// See GzipHttpResponseWriter for detail
func mqttConfig() (*RouteConfig, error) {
	/*
		sudo echo "127.0.0.1 mqtt.testlan.allape.cc" >> /etc/hosts

		echo "listener 1883" > mosquitto.conf
		echo "" >> mosquitto.conf
		echo "allow_anonymous true" >> mosquitto.conf
		echo "listener 1888" >> mosquitto.conf
		echo "protocol websockets" >> mosquitto.conf
		echo "allow_anonymous true" >> mosquitto.conf
		echo "connection_messages true" >> mosquitto.conf
		echo "" >> mosquitto.conf

		docker run \
		  -v "$(pwd)/mosquitto.conf":"/mosquitto/config/mosquitto.conf" \
		  -d \
		  -p 1888:1888 \
		  --name mqtt \
		  --restart=unless-stopped \
		  eclipse-mosquitto

		# test ops
		# open url https://allape.github.io/React-Lyrics/?remoteTouchpadURL=mqtts%3A%2F%2Fmqtt.testlan.allape.cc#remote-touchpad
		# click Connect to test
	*/

	u, err := url.Parse("http://127.0.0.1:1888")
	if err != nil {
		return nil, fmt.Errorf("failed to parse mqtt config: %s", err)
	}

	r := &RouteConfig{
		Name:                 "mqtt",
		Priority:             100,
		Hostname:             "mqtt.testlan.allape.cc",
		URIPrefix:            "",
		AllowPublicAccess:    true,
		StripURIPrefix:       false,
		AccessLimitPerMinute: 60,
		SetHost:              false,
		EnableCompression:    true,

		ForwardTo: u,
	}

	cert, ok, err := testCert()
	if err != nil {
		log.Printf("failed to load test certificate: %s", err)
	} else if !ok {
		log.Printf("no test certificate loaded")
	} else {
		r.Certificate = cert
	}

	return r, nil
}

// dockerRegistryConfig
// Should not redirect from http to https for some method, for example: PATCH
// See CanRedirect2Https for detail
func dockerRegistryConfig() (*RouteConfig, error) {
	/*
		sudo echo "127.0.0.1 docker-registry.testlan.allape.cc" >> /etc/hosts

		docker run -d --name registry -p 5060:5000 --restart=unless-stopped registry:2

		# test ops
		docker pull alpine:3
		docker tag alpine:3 docker-registry.testlan.allape.cc/alpine:3
		docker push docker-registry.testlan.allape.cc/alpine:3
	*/

	u, err := url.Parse("http://127.0.0.1:5060")
	if err != nil {
		return nil, fmt.Errorf("failed to parse docker registry config: %s", err)
	}

	r := &RouteConfig{
		Name:                 "docker-registry",
		Priority:             100,
		Hostname:             "docker-registry.testlan.allape.cc",
		URIPrefix:            "",
		AllowPublicAccess:    true,
		StripURIPrefix:       false,
		AccessLimitPerMinute: 60,
		SetHost:              false,
		EnableCompression:    true,

		ForwardTo: u,
	}

	cert, ok, err := testCert()
	if err != nil {
		log.Printf("failed to load test certificate: %s", err)
	} else if !ok {
		log.Printf("no test certificate loaded")
	} else {
		r.Certificate = cert
	}

	return r, nil
}

// testCert
// *.testlan.allape.cc signed by local cert management
func testCert() (*tls.Certificate, bool, error) {
	cert := "cert/_.testlan.allape.cc.crt"
	pkey := "cert/_.testlan.allape.cc.key"

	stat, err := os.Stat(cert)
	if err != nil {
		return nil, false, fmt.Errorf("could not stat certificate: %w", err)
	} else if stat.IsDir() {
		return nil, false, fmt.Errorf("cert %s is a directory", cert)
	}

	stat, err = os.Stat(pkey)
	if err != nil {
		return nil, false, fmt.Errorf("could not stat private key: %w", err)
	} else if stat.IsDir() {
		return nil, false, fmt.Errorf("pkey %s is a directory", pkey)
	}

	certPEM, err := os.ReadFile(cert)
	if err != nil {
		return nil, false, fmt.Errorf("could not read certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(pkey)
	if err != nil {
		return nil, false, fmt.Errorf("could not read private key: %w", err)
	}

	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, false, fmt.Errorf("could not parse certificate: %w", err)
	}

	return &c, true, nil
}
