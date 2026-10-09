package main

import (
	"log"
	"net/http"
)

func main() {
	const port string = "8080"
	const rootDir string = "."

	mux := http.NewServeMux()

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	mux.Handle("/", http.FileServer(http.Dir(rootDir)))

	log.Printf("Serving on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())
}
