package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Email string `gorm:"unique;not null"`
	Hash string `gorm:"not null"`
	HashedRt string
}
