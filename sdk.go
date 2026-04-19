package gophorward

import (
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	ContextGrantedKey = "x-goor-granted"
	ContextUserKey    = "x-goor-user"
)

type SimpleUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func GinMiddlewareHandler(noUserHandler ...gin.HandlerFunc) gin.HandlerFunc {
	return func(context *gin.Context) {
		id := strings.TrimSpace(context.Request.Header.Get(HeaderUserID))

		if len(id) == 0 {
			for _, handlerFunc := range noUserHandler {
				handlerFunc(context)
			}
			context.Set(ContextGrantedKey, false)
			return
		}

		name := strings.TrimSpace(context.Request.Header.Get(HeaderUserName))

		user := &SimpleUser{id, name}
		context.Set(ContextGrantedKey, true)
		context.Set(ContextUserKey, user)
	}
}

func GinGetUser(context *gin.Context) (*SimpleUser, bool) {
	granted := context.GetBool(ContextGrantedKey)
	if !granted {
		return nil, false
	}

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
