package main

import (
	"log/slog"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/nazwadi/combine/ui"
)

type app struct {
	log  *slog.Logger
	tmpl *template.Template
}

func main() {
	const port string = "8080"

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpl, err := template.ParseFS(ui.Files, "html/*.html")
	if err != nil {
		logger.Error("parsing templates", "err", err)
		os.Exit(1)
	}

	a := &app{log: logger, tmpl: tmpl}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	logger.Info("starting server", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
