package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// 第一个rate limiter是限制平时的请求频率，第二个rate limiter是限制突发请求的数量
func RateLimitMiddleware(r rate.Limit, maxRequests int) gin.HandlerFunc {

	limiter := rate.NewLimiter(r, maxRequests)

	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "请求过于频繁，请稍后再试",
			})
		}
		c.Next()
	}
}
