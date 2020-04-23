package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/alexedwards/scs/engine/memstore"
	"github.com/alexedwards/scs/session"
	"github.com/casbin/casbin"
	"github.com/zupzup/casbin-http-role-example/authorization"
	"github.com/zupzup/casbin-http-role-example/model"
)

func main() {
	// 第一步：创建一个Casbin决策器需要有一个模型文件和策略文件为参数：
	authEnforcer, err := casbin.NewEnforcerSafe("./auth_model.conf", "./policy.csv")
	if err != nil {
		log.Fatal(err)
	}

	/*
		第二步：设置会话管理器。
		我们创建了一个具有 30 分钟超时的内存 session 存储和和一个具备安全 cookie 存储的会话管理器。
		**/
	engine := memstore.New(30 * time.Minute)
	sessionManager := session.Manage(engine, session.IdleTimeout(30*time.Minute), session.Persist(true), session.Secure(true))
	users := createUsers()

	// 第三步：设置路由
	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler(users))
	mux.HandleFunc("/logout", logoutHandler())
	mux.HandleFunc("/member/current", currentMemberHandler())
	mux.HandleFunc("/member/role", memberRoleHandler())
	mux.HandleFunc("/admin/stuff", adminHandler())

	log.Print("Server started on localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", sessionManager(authorization.Authorizer(authEnforcer, users)(mux))))

}

/*
CreateUsers 函数创建了三个不同的用户。
注：在实际应用中，我们会使用数据库来存储用户数据
**/
func createUsers() model.Users {
	users := model.Users{}
	users = append(users, model.User{ID: 1, Name: "Admin", Role: "admin"})
	users = append(users, model.User{ID: 2, Name: "Sabine", Role: "member"})
	users = append(users, model.User{ID: 3, Name: "Sepp", Role: "member"})
	return users
}

/*
登录
从请求中获取到用户名，检查该用户是否存在，若存在，则创建一个新的 session，并将用户角色和 ID 存入 session 中。
**/
func loginHandler(users model.Users) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PostFormValue("name")
		user, err := users.FindByName(name)
		if err != nil {
			writeError(http.StatusBadRequest, "WRONG_CREDENTIALS", w, err)
			return
		}
		// setup ession
		if err := session.RegenerateToken(r); err != nil {
			writeError(http.StatusInternalServerError, "ERROR", w, err)
			return
		}
		session.PutInt(r, "userID", user.ID)
		session.PutString(r, "role", user.Role)
		writeSuccess("SUCCESS", w)
	})
}

/*
注销
创建一个新的空的 session，并从 session 存储中删除旧的 session，注销该用户。
**/
func logoutHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := session.Renew(r); err != nil {
			writeError(http.StatusInternalServerError, "ERROR", w, err)
			return
		}
		writeSuccess("SUCCESS", w)
	})
}

/*
读取请求的userID
**/
func currentMemberHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, err := session.GetInt(r, "userID")
		if err != nil {
			writeError(http.StatusInternalServerError, "ERROR", w, err)
			return
		}
		writeSuccess(fmt.Sprintf("User with ID: %d", uid), w)
	})
}

/*
读取请求的角色
**/
func memberRoleHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role, err := session.GetString(r, "role")
		if err != nil {
			writeError(http.StatusInternalServerError, "ERROR", w, err)
			return
		}
		writeSuccess(fmt.Sprintf("User with Role: %s", role), w)
	})
}

/*
超级管理员
**/
func adminHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSuccess("I'm an Admin!", w)
	})
}

/*
写入session错误
**/
func writeError(status int, message string, w http.ResponseWriter, err error) {
	log.Print("ERROR: ", err.Error())
	w.WriteHeader(status)
	w.Write([]byte(message))
}

/*
写入session成功
**/
func writeSuccess(message string, w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(message))
}
