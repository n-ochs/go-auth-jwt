package initializers

import (
	"go-auth-jwt/models"
)

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
