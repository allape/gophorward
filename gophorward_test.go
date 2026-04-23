package gophorward

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func localhostConfig() (*RouteConfig, error) {
	u, err := url.Parse("http://127.0.0.1:5050") // dufs .
	if err != nil {
		return nil, fmt.Errorf("failed to parse localhost config: %s", err)
	}

	return &RouteConfig{
		Name:                 "localhost",
		Priority:             100,
		Hostname:             "localhost",
		URIPrefix:            "",
		AllowPublicAccess:    true,
		StripURIPrefix:       false,
		AccessLimitPerMinute: 60,
		SetHost:              false,
		EnableCompression:    true,

		ForwardTo: u,
	}, nil
}

func TestNewGophorward(t *testing.T) {
	config1, err := localhostConfig()
	if err != nil {
		t.Fatalf("failed to load localhost config: %s", err)
		return
	}

	server, err := NewGophorward(":80", ":443", []RouteConfig{
		*config1,
	}, []AuthorizedToken{
		{
			Token: "1234567890",
			AllowedRoutes: []RouteName{
				"localhost",
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
