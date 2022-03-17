package main

import (
	"fmt"
	"go-rest-api/app"
	"go-rest-api/controllers"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()
	router.Use(app.JwtAuthentication)

	router.HandleFunc("/api/user/new", controllers.CreateAccount).Methods("POST")

	router.HandleFunc("/api/user/login", controllers.Authenticate).Methods("POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	fmt.Println(port)

	err := http.ListenAndServe(":"+port, router)
	if err != nil {
		fmt.Print(err)
	}
}
