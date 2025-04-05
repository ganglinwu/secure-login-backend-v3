package models

import "time"

type User struct {
	Email      string    `json:"email" validate:"email, required"`
	Password   string    `json:"password" validate:"required"`
	Created_at time.Time `json:"created_at,omitempty"`
	Updated_at time.Time `json:"updated_at,omitempty"`
}
