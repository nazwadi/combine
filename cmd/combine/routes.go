package main

import (
	"net/http"

	"github.com/nazwadi/combine/ui"
)

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.FileServerFS(ui.Files))
	mux.HandleFunc("GET /{$}", a.home)

	return mux
}
