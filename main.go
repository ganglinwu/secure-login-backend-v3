package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ganglinwu/secure-login-v3/controller"
	pg "github.com/ganglinwu/secure-login-v3/db/postgres"
	"github.com/joho/godotenv"
)

func init() {
	// Load .env file
	LoadEnvVariables()
}

func main() {
	// connect to DB
	connString := fmt.Sprintf("user=%s password=%s host=%s dbname=%s sslmode=require", os.Getenv("USERNAME"), os.Getenv("PASSWORD"), os.Getenv("HOSTNAME"), os.Getenv("DATABASE_NAME"))
	conn, err := sql.Open("postgres", connString)
	if err != nil {
		log.Fatal("failed to connect to postgres")
	}

	err = conn.Ping()
	if err != nil {
		log.Fatal("failed to connect to postgres")
	}
	log.Println("connected to postgres database")

	store := pg.NewPostgresStore(conn)
	c := controller.NewLoginServer(store)

	s := http.Server{
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
		Handler:      c,
		Addr:         ":8080",
	}

	go func() {
		err := s.ListenAndServe()
		if err != nil {
			log.Fatal("failed to listen and serve")
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	signal.Notify(sigChan, syscall.SIGTERM)

	sig := <-sigChan
	log.Println("received terminate, shutting down gracefully", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.Shutdown(ctx)
}

func LoadEnvVariables() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("failed to load .env file, please check if it exists in the right directory")
	}
}
