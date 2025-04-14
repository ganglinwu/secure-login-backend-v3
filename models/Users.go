package models

import "time"

type ClientUser struct {
	Email    string `json:"email" validate:"email, required"`
	Password string `json:"password" validate:"required"`
}

type ServerUser struct {
	Email      string    `json:"email" validate:"email, required"`
	HPassword  string    `json:"password"`
	Created_at time.Time `json:"created_at,omitempty"`
	Updated_at time.Time `json:"updated_at,omitempty"`
}
