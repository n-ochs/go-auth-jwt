package main

import (
	"go-auth-jwt/controllers"
	"go-auth-jwt/initializers"
	"go-auth-jwt/middleware"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"*"},
		AllowHeaders:     []string{"Access-Control-Allow-Origin", "Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization", "request_id"},
		ExposeHeaders:    []string{"*"},
		AllowCredentials: true,
		MaxAge: 12 * time.Hour,
	}))

	/* ------------------------------- AUTH ROUTES ------------------------------ */
	r.POST("/api/auth/signup", controllers.SignUp)
	r.POST("/api/auth/signin", controllers.SignIn)
	r.POST("/api/auth/signout", middleware.RequireAccessToken, controllers.SignOut)
	r.GET("/api/auth", middleware.RequireAccessToken, controllers.Validate)
	r.POST("/api/auth/refresh", middleware.RequireRefreshToken, controllers.RefreshToken)

	r.Run()
}
