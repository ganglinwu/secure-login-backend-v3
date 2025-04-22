package jsonWebTokes

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"

	"github.com/ganglinwu/secure-login-v3/errs"
)

func GenAuthToken(email string) (string, error) {
	// TODO: on production server this path is not the same!
	_ = godotenv.Load("/Users/ganglinwu/code/learn-golang/akhil-sharma-tutorials/06a-secure-login-jwt/.env")
	JWT_SECRET_KEY, exists := os.LookupEnv("JWT_SECRET_KEY")
	if !exists {
		return "", errs.EnvVarNotFound
	}
	claims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{
		Issuer:    email,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	})

	token, err := claims.SignedString([]byte(JWT_SECRET_KEY))

	return token, err
}

type MyCustomClaim struct {
	Issuer string `json:"iss"`
	jwt.RegisteredClaims
}

func CheckAuthToken(cookieValue string) (string, error) {
	// TODO: on production server this path is not the same!
	_ = godotenv.Load("/Users/ganglinwu/code/learn-golang/akhil-sharma-tutorials/06a-secure-login-jwt/.env")
	JWT_SECRET_KEY, exists := os.LookupEnv("JWT_SECRET_KEY")
	if !exists {
		return "", errs.EnvVarNotFound
	}
	token, err := jwt.ParseWithClaims(cookieValue, &MyCustomClaim{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(JWT_SECRET_KEY), nil
	}, jwt.WithLeeway(5*time.Minute))
	if err != nil {
		return "", err
	} else if claims, ok := token.Claims.(*MyCustomClaim); ok {
		return claims.Issuer, nil
	}
	return "", error(fmt.Errorf("error parsing cookie"))
}
