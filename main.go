package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/login", Login)
	http.HandleFunc("/dashboard", Dashboard)
	http.HandleFunc("/refresh", Refresh)

	log.Fatal(http.ListenAndServe(":8000", nil))
}

// func main() {
// 	//Init Router
// 	r := mux.NewRouter()

// 	// arrange our route
// 	r.HandleFunc("/api/users", getUsers).Methods("GET")
// 	r.HandleFunc("/api/users/{id}", getUser).Methods("GET")
// 	r.HandleFunc("/api/users", createUser).Methods("POST")
// 	r.HandleFunc("/api/users/{id}", updateUser).Methods("PUT")
// 	r.HandleFunc("/api/users/{id}", deleteUser).Methods("DELETE")

// 	// set our port address
// 	log.Fatal(http.ListenAndServe(":9000", r))
// }
