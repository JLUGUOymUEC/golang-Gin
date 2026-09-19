package service

import (
	"fmt"
	// "crypto/sha256" //使用标准库的sha256包进行密码哈希处理，不推荐
	"golang.org/x/crypto/bcrypt" //推荐使用bcrypt进行密码哈希处理,单向哈希没法复原
)

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("Password cannot be empty")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost) //加盐每次生成的哈希值都不一样,所以不能直接比较哈希值,需要使用bcrypt.CompareHashAndPassword进行验证
	if err != nil {
		return "", fmt.Errorf("Failed to hash password: %w ", err)
	}
	return fmt.Sprintf("%x", hashedPassword), nil
}


//加盐对比方法
func VerifyPassword(password string, hashedPassword string) bool {
	return (bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))) == nil
}