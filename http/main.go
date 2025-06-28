package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    input := r.URL.Query().Get("input")
    if input == "" {
        http.Error(w, "Missing 'input' query parameter", http.StatusBadRequest)
        return
    }

    fmt.Fprintf(w, "You sent: %s\n", input)
}

func main() {
    http.HandleFunc("/", handler)
    fmt.Println("Server started at http://localhost:8084")
    http.ListenAndServe(":8084", nil)
}

