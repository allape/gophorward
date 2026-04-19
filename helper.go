package gophorward

import (
	"encoding/json"
	"fmt"
	"net/http"
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

func CanRedirect2Https(request *http.Request) bool {
	switch request.Method {
	case "HEAD", "GET", "POST", "PUT", "OPTIONS":
		return true
	}
	return false
}
