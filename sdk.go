package gophorward

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	ContextUserKey = "x-goor-user"
)

type SimpleUser struct {
	ID   UserID   `json:"id"`
	Name UserName `json:"name"`
}

func GinMiddlewareHandler(noUserHandler ...gin.HandlerFunc) gin.HandlerFunc {
	return func(context *gin.Context) {
		user, ok := HttpGetUser(context.Request)

		if !ok {
			for _, handlerFunc := range noUserHandler {
				handlerFunc(context)
			}
			return
		}

		context.Set(ContextUserKey, user)
	}
}

func GinGetUser(context *gin.Context) (*SimpleUser, bool) {
	user, ok := context.Get(ContextUserKey)
	if !ok {
		return nil, false
	}

	parsedUser, ok := user.(*SimpleUser)
	if !ok {
		return nil, false
	}

	return parsedUser, true
}

func HttpGetUser(request *http.Request) (*SimpleUser, bool) {
	return HttpHeaderGetUser(request.Header)
}

func HttpHeaderGetUser(header http.Header) (*SimpleUser, bool) {
	id := strings.TrimSpace(header.Get(HeaderUserID))

	if id == "" {
		return nil, false
	}

	return &SimpleUser{
		ID:   UserID(id),
		Name: UserName(header.Get(HeaderUserName)),
	}, true
}
