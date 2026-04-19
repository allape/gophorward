package gophorward

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/allape/gogger"
)

const ServerName = "Goor"

var httpl = gogger.New("forwarder:http")
var httpsl = gogger.New("forwarder:https")

const (
	HeaderAuthorization = "X-Goor-Authorization"
	HeaderUserID        = "X-Goor-User-ID"
	HeaderUserName      = "X-Goor-User-Name"

	CookieTokenKey = "x-goor-token"

	QueryNextURLName = "xgoornext"
)

var (
	Error401 = errors.New("401 Unauthorized")
	Error403 = errors.New("403 Forbidden")
	Error404 = errors.New("404 Not Found")
	Error500 = errors.New("500 Internal Server Error")
	Error429 = errors.New("429 Too Many Requests")
)

type RequestConfig struct {
	RouteConfig  *RouteConfig
	ReverseProxy *httputil.ReverseProxy
}

type (
	AuthorizedTokenMap map[Token]AuthorizedToken
	RequestConfigMap   map[Hostname]map[URIPrefix]*RequestConfig
)

type Gophorward struct {
	httpServer  *http.Server
	httpsServer *http.Server

	running bool

	ServerName string
	HttpAddr   string
	HttpsAddr  string

	MakeResponse func(writer http.ResponseWriter, request *http.Request, statusCode int, message string, err error)

	RouteConfigs []RouteConfig

	accessCounter *AccessCounter

	tokenLocker      sync.Mutex
	authorizedTokens AuthorizedTokenMap

	AuthorizationHeaderKey string // default is HeaderAuthorization, do NOT edit it when serving, higher priority than below
	AuthorizationCookieKey string // default is CookieTokenKey, do NOT edit it when serving

	RedirectURLFor401 *url.URL
	// RedirectNextURLQueryName
	// The query name to store current URL, default is QueryNextURLName
	// For example:
	//   User open URL https://private/api/me without token,
	//   then Goor will redirect to https://login?xgoornext=https%3A%2F%2Fprivate%2Fapi%2Fme
	RedirectNextURLQueryName string

	CleanerInterval time.Duration

	// BeforeForward
	// DO NOT DO A BLOCKING IN THIS FUNC
	BeforeForward func(
		userId UserID, // This will be 0 if a route is public accessible
		routeName RouteName, // Name of current route
		originalURI string, // URI before trim (if set to be trimmed)
		forwardTo string, //
		consoleMessage string, // The message which logged to the std console
		request *http.Request,
	)
}

func (f *Gophorward) startCleaner(endChan <-chan struct{}) {
	if f.CleanerInterval <= 0 {
		f.CleanerInterval = time.Hour
	}

	ended := false

	go func() {
		for {
			if ended {
				break
			}
			time.Sleep(f.CleanerInterval)

			func() {
				f.tokenLocker.Lock()
				defer f.tokenLocker.Unlock()

				for token, session := range f.authorizedTokens {
					if time.Now().After(session.ExpireAt) {
						delete(f.authorizedTokens, token)
					}
				}
			}()
		}
	}()

	go func() {
		for {
			if ended {
				break
			}
			time.Sleep(f.CleanerInterval)

			f.accessCounter.CleanUp()
		}
	}()

	go func() {
		<-endChan
		ended = true
	}()
}

func (f *Gophorward) endWith401(writer http.ResponseWriter, request *http.Request) {
	if f.RedirectURLFor401 == nil || IsJSON(request) {
		f.MakeResponse(writer, request, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), Error401)
	} else {
		request.URL.Scheme = "http"
		if IsHttps(request) {
			request.URL.Scheme = "https"
		}
		request.URL.Host = request.Host

		u, _ := url.Parse(f.RedirectURLFor401.String())
		query := u.Query()
		query.Set(f.RedirectNextURLQueryName, request.URL.String())
		u.RawQuery = query.Encode()
		http.Redirect(writer, request, u.String(), http.StatusFound)
	}
}

func (f *Gophorward) prepare() error {
	if f.AuthorizationHeaderKey == "" {
		f.AuthorizationHeaderKey = HeaderAuthorization
	}

	if f.AuthorizationCookieKey == "" {
		f.AuthorizationCookieKey = CookieTokenKey
	}

	if f.RedirectNextURLQueryName == "" {
		f.RedirectNextURLQueryName = QueryNextURLName
	}

	if f.ServerName == "" {
		f.ServerName = ServerName
	}

	if f.MakeResponse == nil {
		f.MakeResponse = MakeResponse
	}

	slices.SortFunc(f.RouteConfigs, func(a, b RouteConfig) int {
		return int(b.Priority - a.Priority)
	})

	return nil
}

func (f *Gophorward) modifyResponseHandler(config *RouteConfig) func(r *http.Response) error {
	return func(r *http.Response) error {
		if location := r.Header.Get("Location"); location != "" {
			// 0 > /music/ui/index.html > 1
			// 1 > /ui/index.html       > 2
			// 1 < Location: ./         < 2
			// 0 < Location: /music/ui/ < 1
			if location == "./" {
				seg := strings.Split(r.Request.RequestURI, "/")
				if len(seg) > 1 {
					seg = seg[0 : len(seg)-1]
				}
				location = strings.Join(seg, "/") + "/"
			}
			r.Header.Set("Location", string(config.URIPrefix)+location)
		}
		return nil
	}
}

// region AuthorizedToken

func (f *Gophorward) AddToken(token AuthorizedToken) error {
	if strings.TrimSpace(string(token.Token)) == "" {
		return errors.New("token is empty")
	} else if time.Now().After(token.ExpireAt) {
		return errors.New("token is expired")
	}

	f.tokenLocker.Lock()
	defer f.tokenLocker.Unlock()

	f.authorizedTokens[token.Token] = token

	return nil
}

func (f *Gophorward) RemoveToken(token Token) bool {
	f.tokenLocker.Lock()
	defer f.tokenLocker.Unlock()

	_, ok := f.authorizedTokens[token]
	if !ok {
		return false
	}
	delete(f.authorizedTokens, token)

	return true
}

func (f *Gophorward) RemoveTokensByUserID(userID UserID) bool {
	f.tokenLocker.Lock()
	defer f.tokenLocker.Unlock()

	tokenKeysForRemove := make([]Token, 0)
	for token, authorizedToken := range f.authorizedTokens {
		if authorizedToken.UserID == userID {
			tokenKeysForRemove = append(tokenKeysForRemove, token)
		}
	}

	for _, token := range tokenKeysForRemove {
		delete(f.authorizedTokens, token)
	}

	return len(tokenKeysForRemove) == 0
}

func (f *Gophorward) GetToken(token Token) (AuthorizedToken, bool) {
	f.tokenLocker.Lock()
	defer f.tokenLocker.Unlock()
	t, ok := f.authorizedTokens[token]
	return t, ok
}

func (f *Gophorward) GetTokens() ([]AuthorizedToken, error) {
	f.tokenLocker.Lock()
	defer f.tokenLocker.Unlock()

	tokens := make([]AuthorizedToken, len(f.authorizedTokens))
	i := 0

	for _, token := range f.authorizedTokens {
		tokens[i] = token
		i++
	}

	return tokens, nil
}

func (f *Gophorward) SetTokens(tokens []AuthorizedToken) {
	f.tokenLocker.Lock()
	defer f.tokenLocker.Unlock()

	tokenMap := make(AuthorizedTokenMap, len(tokens))
	for _, token := range tokens {
		tokenMap[token.Token] = token
	}

	f.authorizedTokens = tokenMap
}

// endregion

func (f *Gophorward) IsRunning() bool {
	return f.running
}

func (f *Gophorward) Shutdown(c context.Context) error {
	if f.httpServer != nil {
		c1, cancel := context.WithCancel(c)
		defer cancel()
		_ = f.httpServer.Close()
		_ = f.httpServer.Shutdown(c1)
		f.httpServer = nil
	}

	if f.httpsServer != nil {
		c2, cancel := context.WithCancel(c)
		defer cancel()
		_ = f.httpsServer.Close()
		_ = f.httpsServer.Shutdown(c2)
		f.httpsServer = nil
	}

	return nil
}

// Serve
// This func does not use any lock, lock it in the caller
func (f *Gophorward) Serve() error {
	c, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := f.Shutdown(c)
	if err != nil {
		return err
	}

	err = f.prepare()
	if err != nil {
		return err
	}

	configCount := len(f.RouteConfigs)

	if configCount == 0 {
		return errors.New("no route configs found")
	}

	configMap := make(RequestConfigMap)

	var certificates []tls.Certificate
	hostnameHasCertificate := make(map[Hostname]bool, configCount)

	for index := range f.RouteConfigs {
		config := f.RouteConfigs[index]

		config.forwardToString = config.ForwardTo.String()

		hostname := config.Hostname
		uriPrefix := config.URIPrefix

		proxy := httputil.NewSingleHostReverseProxy(config.ForwardTo)
		if config.ForwardTrustedCertPool != nil {
			t := http.DefaultTransport.(*http.Transport).Clone()
			t.TLSClientConfig.RootCAs = config.ForwardTrustedCertPool
			proxy.Transport = t
		}

		if config.StripURIPrefix {
			proxy.ModifyResponse = f.modifyResponseHandler(&config)
		}

		if m, ok := configMap[hostname]; !ok || m == nil {
			configMap[hostname] = make(map[URIPrefix]*RequestConfig)
		}

		configMap[hostname][uriPrefix] = &RequestConfig{
			RouteConfig:  &config,
			ReverseProxy: proxy,
		}

		if config.Certificate != nil {
			certificates = append(certificates, *config.Certificate)
			hostnameHasCertificate[hostname] = true
		} else {
			hostnameHasCertificate[hostname] = false
		}
	}

	newHandler := func(isHttps bool) http.Handler {
		l := httpl
		//goland:noinspection HttpUrlsUsage
		protocolPrefix := "http://"
		if isHttps {
			l = httpsl
			protocolPrefix = "https://"
		}

		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			hostname := Hostname(request.Host)

			if /*!isHttps && */ !IsHttps(request) && CanRedirect2Https(request) {
				if hasCertificate, ok := hostnameHasCertificate[hostname]; ok && hasCertificate {
					http.Redirect(writer, request, "https://"+request.Host+request.URL.String(), http.StatusPermanentRedirect)
					return
				}
			}

			writer.Header().Set("Server", f.ServerName)

			uriConfigMap, ok := configMap[hostname]
			if !ok {
				l.Info().Printf("[%s] -> [%s%s] -> 404.host", request.RemoteAddr, request.Host, request.RequestURI)
				f.MakeResponse(writer, request, http.StatusNotFound, http.StatusText(http.StatusNotFound), Error404)
				return
			}

			var requestConfig *RequestConfig

			for prefix, rc := range uriConfigMap {
				if strings.HasPrefix(request.RequestURI, string(prefix)) {
					requestConfig = rc
					break
				}
			}

			if requestConfig == nil {
				l.Info().Printf("[%s] -> [%s%s] -> 404.uriprefix", request.RemoteAddr, request.Host, request.RequestURI)
				f.MakeResponse(writer, request, http.StatusNotFound, http.StatusText(http.StatusNotFound), Error404)
				return
			}

			proxy := requestConfig.ReverseProxy
			if proxy == nil {
				l.Error().Printf("[%s] -> [%s%s] -> 500.proxy", request.RemoteAddr, request.Host, request.RequestURI)
				f.MakeResponse(writer, request, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), Error500)
				return
			}

			routeConfig := requestConfig.RouteConfig
			if routeConfig == nil {
				l.Error().Printf("[%s] -> [%s%s] -> 500.config", request.RemoteAddr, request.Host, request.RequestURI)
				f.MakeResponse(writer, request, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), Error500)
				return
			}

			if routeConfig.AccessLimitPerMinute > 0 && !f.accessCounter.CanAccess(
				routeConfig.GetClientIdentity(request),
				routeConfig.AccessLimitPerMinute,
			) {
				f.MakeResponse(writer, request, http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests), Error429)
				return
			}

			userId := UserID("0")

			if routeConfig.AllowPublicAccess {
				request.Header.Del(HeaderUserID)
				request.Header.Del(HeaderUserName)
			} else {
				token := request.Header.Get(f.AuthorizationHeaderKey)
				if token == "" {
					cookie, err := request.Cookie(f.AuthorizationCookieKey)
					if err == nil {
						token, _ = url.QueryUnescape(cookie.Value)
					}
				}

				if token == "" {
					f.endWith401(writer, request)
					return
				}

				session, ok := f.GetToken(Token(token))
				if !ok {
					f.endWith401(writer, request)
					return
				} else if time.Now().After(session.ExpireAt) {
					f.endWith401(writer, request)
					return
				}

				if !slices.Contains(session.AllowedRoutes, routeConfig.Name) {
					f.MakeResponse(writer, request, http.StatusForbidden, http.StatusText(http.StatusForbidden), Error403)
					return
				}

				userId = session.UserID
				request.Header.Set(HeaderUserID, string(userId))
				request.Header.Set(HeaderUserName, string(session.UserName))

				if session.AppendHeaders != nil {
					for header, values := range session.AppendHeaders {
						for _, value := range values {
							request.Header.Add(header, value)
						}
					}
				}
			}

			// not pass token to next server
			request.Header.Del(f.AuthorizationHeaderKey)
			cookies := request.Cookies()
			request.Header.Del("Cookie")
			for _, cookie := range cookies {
				if cookie.Name != f.AuthorizationCookieKey {
					request.AddCookie(cookie)
				}
			}

			originalURI := request.RequestURI
			if routeConfig.StripURIPrefix {
				request.RequestURI = strings.TrimPrefix(request.RequestURI, string(routeConfig.URIPrefix))
				request.URL.Path = request.RequestURI
			}

			consoleMessage := fmt.Sprintf(
				"%s@%s %s %s%s%s -> %s%s",
				userId,
				request.RemoteAddr,
				request.Method,
				protocolPrefix, request.Host, originalURI,
				routeConfig.forwardToString, request.RequestURI,
			)
			l.Info().Print(consoleMessage)

			if f.BeforeForward != nil {
				f.BeforeForward(
					userId,
					routeConfig.Name,
					originalURI,
					routeConfig.forwardToString,
					consoleMessage,
					request,
				)
			}

			if routeConfig.DownHeaders != nil {
				for header, values := range routeConfig.DownHeaders {
					for _, value := range values {
						request.Header.Add(header, value)
					}
				}
			}

			if routeConfig.UpHeaders != nil {
				headers := writer.Header()
				for header, values := range routeConfig.UpHeaders {
					for _, value := range values {
						headers.Add(header, value)
					}
				}
			}

			if routeConfig.SetHost {
				request.Host = routeConfig.ForwardTo.Hostname()
			}

			proxy.ServeHTTP(writer, request)
		})
	}

	noServerStarted := true

	var wait sync.WaitGroup

	if f.HttpAddr != "" {
		wait.Add(1)
		noServerStarted = false

		f.httpServer = &http.Server{
			Addr:    f.HttpAddr,
			Handler: newHandler(false),
		}

		go func() {
			defer func() {
				wait.Done()
			}()

			httpl.Info().Printf("http forwarder start on %s", f.HttpAddr)

			err := f.httpServer.ListenAndServe()
			if !errors.Is(err, http.ErrServerClosed) {
				httpl.Error().Printf("http server error: %s", err)
			}
		}()
	}

	if f.HttpsAddr != "" && len(certificates) > 0 {
		wait.Add(1)
		noServerStarted = false

		f.httpsServer = &http.Server{
			Addr:    f.HttpsAddr,
			Handler: newHandler(true),
			TLSConfig: &tls.Config{
				Certificates: certificates,
			},
		}

		go func() {
			defer func() {
				wait.Done()
			}()

			httpsl.Info().Printf("https forwarder start on %s", f.HttpsAddr)

			err := f.httpsServer.ListenAndServeTLS("", "")
			if !errors.Is(err, http.ErrServerClosed) {
				httpsl.Error().Printf("https server error: %s", err)
			}
		}()
	}

	if noServerStarted {
		return errors.New("no server started")
	}

	f.running = true
	defer func() {
		f.running = false
	}()

	cleanerStopper := make(chan struct{})
	f.startCleaner(cleanerStopper)

	wait.Wait()

	cleanerStopper <- struct{}{}

	return err
}

// NewGophorward
// TODO test
func NewGophorward(httpAddr, httpsAddr string, configs []RouteConfig, tokens []AuthorizedToken) (*Gophorward, error) {
	httpAddr = strings.TrimSpace(httpAddr)
	httpsAddr = strings.TrimSpace(httpsAddr)

	if httpAddr == "" && httpsAddr == "" {
		return nil, errors.New("no http address or https address provided")
	}

	f := &Gophorward{
		ServerName:   ServerName,
		HttpAddr:     httpAddr,
		HttpsAddr:    httpsAddr,
		RouteConfigs: configs,

		MakeResponse: MakeResponse,

		accessCounter: NewAccessCounter(time.Minute),
	}

	f.SetTokens(tokens)

	return f, nil
}
