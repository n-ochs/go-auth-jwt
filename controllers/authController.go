package controllers

import (
	"crypto/subtle"
	"fmt"
	"go-auth-jwt/initializers"
	"go-auth-jwt/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(c *gin.Context) {
	// Get email/pass off req body
	var body struct {
		Email string
		Password string
	}
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	// Create user
	user := models.User{Email: body.Email, Hash: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	// Respond
	c.JSON(http.StatusCreated, gin.H{})
}

func SignIn(c *gin.Context) {
	// Get email/pass off req body
	var body struct {
		Email string
		Password string
	}
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	// Look up requested user
	var user models.User
	userResult := initializers.DB.First(&user, "email = ?", body.Email)
	if userResult.Error != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	// Compare pass with hashed pass
	err := bcrypt.CompareHashAndPassword([]byte(user.Hash), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	// Generate JWT tokens
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"email": user.Email,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	})
	accessTokenString, accessTokenStringErr := accessToken.SignedString([]byte(os.Getenv("AT_SECRET")))
	
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"email": user.Email,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	})
	refreshTokenString, refreshTokenStringErr := refreshToken.SignedString([]byte(os.Getenv("RT_SECRET")))

	if accessTokenStringErr != nil || refreshTokenStringErr != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Failed to create tokens",
		})
		return;
	}

	// Update RT hash in DB
    salt := make([]byte, 16)
    
    hashedRt := argon2.IDKey([]byte(refreshTokenString), salt, 1, 64*1024, 4, 32)
	hashedRtString := fmt.Sprintf("%x", hashedRt)
	
	updateUserResult := initializers.DB.Model(&user).Update("hashed_rt", hashedRtString)
	if updateUserResult.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to update hashed refresh token",
		})
		return
	}

	// Send as cookies
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("accessToken", accessTokenString, 900000, "/", "localhost", true, true)
	c.SetCookie("refreshToken", refreshTokenString, 7200000, "/api/auth/refresh", "localhost", true, true)
}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}

func RefreshToken(c *gin.Context) {
	refreshTokenString, _ := c.Get("refreshTokenString")
	sub, _ := c.Get("sub")

	// Find the user
	var user models.User
	userResult := initializers.DB.First(&user, "id = ?", sub)
	if userResult.Error != nil {
		c.SetCookie("refreshToken", "", -1, "/api/auth/refresh", "localhost", true, true)
		c.AbortWithStatus(http.StatusUnauthorized)

		c.JSON(http.StatusForbidden, gin.H{
			"error": "Problem finding user in DB",
		})
		return
	}

	// Verify refreshTokenString & hashedRt match
	salt := make([]byte, 16)
    
    hashedIncomingRefreshToken := argon2.IDKey([]byte(refreshTokenString.(string)), salt, 1, 64*1024, 4, 32)
	hashedIncomingRefreshTokenString := fmt.Sprintf("%x", hashedIncomingRefreshToken)
	if subtle.ConstantTimeCompare([]byte(user.HashedRt), []byte(hashedIncomingRefreshTokenString)) == 1 {
        // Generate JWT tokens
		accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": user.ID,
			"email": user.Email,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 15).Unix(),
		})
		accessTokenString, accessTokenStringErr := accessToken.SignedString([]byte(os.Getenv("AT_SECRET")))
		
		refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": user.ID,
			"email": user.Email,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 15).Unix(),
		})
		refreshTokenString, refreshTokenStringErr := refreshToken.SignedString([]byte(os.Getenv("RT_SECRET")))

		if accessTokenStringErr != nil || refreshTokenStringErr != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Failed to create tokens",
			})
			return;
		}

		// Update RT hash in DB
		salt := make([]byte, 16)
		
		hashedRt := argon2.IDKey([]byte(refreshTokenString), salt, 1, 64*1024, 4, 32)
		hashedRtString := fmt.Sprintf("%x", hashedRt)
		
		updateUserResult := initializers.DB.Model(&user).Update("hashed_rt", hashedRtString)
		if updateUserResult.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to update hashed refresh token",
			})
			return
		}

		// Send as cookies
		c.SetSameSite(http.SameSiteStrictMode)
		c.SetCookie("accessToken", accessTokenString, 900000, "/", "localhost", true, true)
		c.SetCookie("refreshToken", refreshTokenString, 7200000, "/api/auth/refresh", "localhost", true, true)
		c.JSON(http.StatusOK, gin.H{
			"message": "Token refreshed successfully",
		})
    } else {
		// If doesnt match, reset hashedRt in DB, clear cookie, abort
		clearHashedRtResult := initializers.DB.Model(&user).Update("hashed_rt", nil)
		if clearHashedRtResult.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to clear hashed RT in DB",
			})
			return
		}
        c.SetCookie("accessToken", "", -1, "/", "localhost", true, true)
        c.SetCookie("refreshToken", "", -1, "/api/auth/refresh", "localhost", true, true)
		c.AbortWithStatus(http.StatusUnauthorized)
    }
}

func SignOut(c *gin.Context) {
	userFromAt, _ := c.Get("user")

	var user models.User
	initializers.DB.First(&user, "id = ?", userFromAt.(models.User).ID)

	updateUserResult := initializers.DB.Model(&user).Update("hashed_rt", nil)
	if updateUserResult.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update hashed refresh token",
		})
		return
	}

	c.SetCookie("accessToken", "", -1, "/", "localhost", true, true)
    c.SetCookie("refreshToken", "", -1, "/api/auth/refresh", "localhost", true, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully signed out",
	})
}