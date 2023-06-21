package middleware

import (
	"fmt"
	"go-auth-jwt/initializers"
	"go-auth-jwt/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAccessToken(c *gin.Context) {
	// Get cookie from request
	accessTokenString, err := c.Cookie("accessToken")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	// Decode & validate
	token, err := jwt.Parse(accessTokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("AT_SECRET")), nil
	})

	if err != nil || token == nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// Find user with token sub 
		var user models.User
		result := initializers.DB.Select("id, created_at", "updated_at", "deleted_at", "email").First(&user, claims["sub"])

		if result.Error != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// Attach to request
		c.Set("user", user)

		// Continue
		c.Next()
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

func RequireRefreshToken(c *gin.Context) {
	// Get cookie from request
	refreshTokenString, err := c.Cookie("refreshToken")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	// Decode & validate
	token, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("RT_SECRET")), nil
	})

	if err != nil || token == nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// Find user with token sub 
		var user models.User
		result := initializers.DB.Select("id, created_at", "updated_at", "deleted_at", "email").First(&user, claims["sub"])

		if result.Error != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// Attach to request
		c.Set("refreshTokenString", refreshTokenString)
		c.Set("sub", claims["sub"])

		// Continue
		c.Next()
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}