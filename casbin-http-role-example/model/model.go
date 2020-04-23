package model

import "errors"

// 用户模型
type User struct {
	ID   int
	Name string
	Role string
}

// 用户列表数组
type Users []User

// Exists 检查列表中是否存在具有给定id的用户.
func (u Users) Exists(id int) bool {
	exists := false
	for _, user := range u {
		if user.ID == id {
			return true
		}
	}
	return exists
}

// FindByName 返回具有给定名称的用户，或者返回错误.
func (u Users) FindByName(name string) (User, error) {
	for _, user := range u {
		if user.Name == name {
			return user, nil
		}
	}
	return User{}, errors.New("USER_NOT_FOUND")
}
