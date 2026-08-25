package api

import "github.com/gin-gonic/gin"

// Fixture: gin-style routes. The unguarded /users route MUST fire; the
// /admin/stats route with AuthMiddleware() in its chain MUST NOT.
func RegisterRoutes(router *gin.Engine) {
	api := router.Group("/api")

	api.GET("/users", listUsers)
	api.POST("/users", createUser)

	admin := router.Group("/admin")
	admin.GET("/stats", AuthMiddleware(), adminStats)
}

func AuthMiddleware() gin.HandlerFunc { return nil }
