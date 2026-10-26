package gophorward

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func IsHttps(request *http.Request) bool {
	return request.TLS != nil
}

func IsJSON(request *http.Request) bool {
	accept := request.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

func MakeResponse(writer http.ResponseWriter, request *http.Request, statusCode int, message string, err error) {
	if IsJSON(request) {
		msg, _ := json.Marshal(map[string]any{
			"code":    strconv.Itoa(statusCode),
			"message": message,
		})

		h := writer.Header()
		h.Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			h.Del("Content-Length")
			h.Set("X-Content-Type-Options", "nosniff")
		}
		writer.WriteHeader(statusCode)

		if len(msg) == 0 {
			h.Del("Content-Length")
			_, _ = fmt.Fprintln(writer, message)
		} else {
			h.Set("Content-Length", strconv.Itoa(len(msg)))
			_, _ = fmt.Fprintln(writer, string(msg))
		}
	} else {
		http.Error(writer, message, statusCode)
	}
}

// CanRedirect2Https
// Credit: https://github.com/caddyserver/caddy d2c46d0b0bc4ec2c8529a3ad24015838356dd888 modules/caddyhttp/httpredirectlistener.go:163
func CanRedirect2Https(request *http.Request) bool {
	switch request.Method {
	case "HEAD", "GET", "POST", "PUT", "OPTIONS":
		return true
	}
	return false
}

func MustTrimHttpValue(value string) (string, error) {
	if value == "" {
		return value, nil
	}

	v, err := url.PathUnescape(value)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(v), nil
}

func HttpValueMapFunc[T any](src []T, stringFn func(T) string) ([]string, error) {
	if len(src) == 0 {
		return nil, nil
	}

	values := make([]string, 0, len(src))

	for _, s := range src {
		v, err := MustTrimHttpValue(stringFn(s))
		if err != nil {
			return nil, err
		} else if v == "" {
			continue
		}
		values = append(values, v)
	}

	return values, nil
}

// GetValuesThroughCookieHeaderQuery
// Get string value from cookies first,
//
//	then from header if empty,
//	then from query/searchparams if empty again
func GetValuesThroughCookieHeaderQuery(request *http.Request, key string) ([]string, error) {
	values, err := HttpValueMapFunc(request.CookiesNamed(key), func(cookie *http.Cookie) string {
		return cookie.Value
	})
	if err != nil {
		return nil, err
	}
	if len(values) > 0 {
		return values, nil
	}

	values, err = HttpValueMapFunc(request.Header.Values(key), func(value string) string { return value })
	if err != nil {
		return nil, err
	}
	if len(values) > 0 {
		return values, nil
	}

	values, err = HttpValueMapFunc(request.URL.Query()[key], func(value string) string { return value })
	if err != nil {
		return nil, err
	}
	if len(values) > 0 {
		return values, nil
	}

	return nil, nil
}

func DeleteThroughCookieHeaderQuery(request *http.Request, key string) error {
	request.Header.Del(key)

	cookies := request.Cookies()
	request.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != key {
			request.AddCookie(cookie)
		}
	}

	query := request.URL.Query()
	query.Del(key)
	request.URL.RawQuery = query.Encode()

	return nil
}
