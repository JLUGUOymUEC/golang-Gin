package handler

import (
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/user/service"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	userService *service.UserService
}

type UserResponse struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	CreatedAt int64  `json:"created_at"`
}

// GET /users?limit=20 第二次 GET /users?limit=20&next_token=eyJ1c2VyX2lkIjoiMiJ9
func (h *UserHandler) ListUsers(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	nextToken := c.Query("next_token")
	users, nextToken, err := h.userService.ListUsers(c.Request.Context(), int32(limit), nextToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"users":      users,
		"next_token": nextToken,
	})
}

// GET    /users/:id
func (h *UserHandler) GetUserByID(c *gin.Context) {
	user_id, ok := middleware.GetCurrentUserID(c)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Can't get userid from middleware"})
		return
	}
	user, err := h.userService.GetUserByID(c.Request.Context(), user_id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := UserResponse{
		UserID:    user.UserID,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}
	c.JSON(http.StatusOK, gin.H{
		"user": resp,
	})
	return
}

// DELETE /users/:id
func (h *UserHandler) DeleteUser(c *gin.Context)
