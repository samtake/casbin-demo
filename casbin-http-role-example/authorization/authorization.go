package authorization

import (
	"casbin-demo/model"
	"errors"
	"log"
	"net/http"

	"github.com/alexedwards/scs/session"
	"github.com/casbin/casbin"
)

// Authorizer 鉴权中间件 .
func Authorizer(e *casbin.Enforcer, users model.Users) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			//通过 session.GetInt 和 session.GetString 来获取当前 session 中的值,从而获取到请求用户的角色
			role, err := session.GetString(r, "role")
			if err != nil {
				writeError(http.StatusInternalServerError, "ERROR", w, err)
				return
			}

			//若用户没有角色，设置为 anonymous 角色
			if role == "" {
				role = "anonymous"
			}
			// 若用户角色为 member，我们将 session 中的 useID 和用户列表相比对，来判断用户是否合法
			if role == "member" {
				uid, err := session.GetInt(r, "userID")
				if err != nil {
					writeError(http.StatusInternalServerError, "ERROR", w, err)
					return
				}
				exists := users.Exists(uid)
				if !exists {
					writeError(http.StatusForbidden, "FORBIDDEN", w, errors.New("user does not exist"))
					return
				}
			}

			/*
				执行 casbin ：
				将用户角色，请求路径和请求方法传给 casbin 执行器，
				执行器决定了具有该角色（ subject ）的用户是否允许访问由该请求方法（ action ）和路径（ object ）指定的资源。
				若校验失败，则返回 403 ，
				若通过，则调用包装的 http 处理函数，允许用户访问请求资源。

				总结：
				正如主函数中提及的，session 管理器和鉴权器对路由进行了包装，所以每个请求都需要通过这个中间件，确保了安全性。​我们可以通过登陆不同的用户，用 curl 或 postman 访问上述的处理函数来测试效果
				**/
			res, err := e.EnforceSafe(role, r.URL.Path, r.Method)
			if err != nil {
				writeError(http.StatusInternalServerError, "ERROR", w, err)
				return
			}
			if res {
				next.ServeHTTP(w, r)
			} else {
				writeError(http.StatusForbidden, "FORBIDDEN", w, errors.New("unauthorized"))
				return
			}
		}

		return http.HandlerFunc(fn)
	}
}

func writeError(status int, message string, w http.ResponseWriter, err error) {
	log.Print("ERROR: ", err.Error())
	w.WriteHeader(status)
	w.Write([]byte(message))
}
