package gophorward

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type String string

func (s String) SpaceTrimmed() String {
	return String(strings.TrimSpace(string(s)))
}

type (
	RouteName String
	Hostname  String
	URIPrefix String
)

type RouteConfig struct {
	Name                 RouteName `json:"name"`                 // unique name
	Priority             uint64    `json:"priority"`             // bigger for higher priority
	Hostname             Hostname  `json:"hostname"`             // hostname for capture, full text comparison, should not contain any slash(/)
	URIPrefix            URIPrefix `json:"uriPrefix"`            // secondary match after hostname, only match prefix, use Priority to control the access order
	AllowPublicAccess    bool      `json:"allowPublicAccess"`    // able to access without an AuthorizedToken
	StripURIPrefix       bool      `json:"stripURIPrefix"`       // remove URIPrefix from RequestURI before append it to ForwardTo
	AccessLimitPerMinute uint64    `json:"accessLimitPerMinute"` // 0 to allow unlimited access
	SetHost              bool      `json:"setHost"`              // set request.Host of http.HandlerFunc to the hostname of ForwardTo

	ForwardTo              *url.URL // must start with `http://` or `https://`
	Certificate            *tls.Certificate
	ForwardTrustedCertPool *x509.CertPool

	UpHeaders   http.Header // headers responses to client, put cors headers here if needed
	DownHeaders http.Header // headers sends to downstream, put extra auth headers here if needed

	forwardToString string
}

// GetClientIdentity
// Generate a string key to identify an access user
func (c *RouteConfig) GetClientIdentity(request *http.Request) AccessCounterKey {
	seg := strings.Split(request.RemoteAddr, ":")
	if len(seg) > 1 {
		seg = seg[0 : len(seg)-1]
	}
	return AccessCounterKey(strings.Join(seg, ":") + ">" + string(c.Name))
}

type (
	Token    string
	UserID   string
	UserName string
)

type AuthorizedToken struct {
	Token         Token       `json:"token"`
	AllowedRoutes []RouteName `json:"allowedRoutes"` // RouteConfig.Name
	AppendHeaders http.Header `json:"appendHeaders"` // not used for now
	ExpireAt      time.Time   `json:"expireAt"`

	UserID   UserID   `json:"userId"`   // unique id
	UserName UserName `json:"userName"` // human-readable name
}
