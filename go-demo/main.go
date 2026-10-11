package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	configPath := flag.String("config", "config.json", "local configuration file")
	flag.Parse()
	c, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	store, err := openStore(c.DataDir)
	if err != nil {
		log.Fatal("cannot open local store; check data_dir, permissions, corrupt store.json, or another running demo; existing files were not reset")
	}
	defer store.Close()
	secrets, err := loadSecrets(c)
	if err != nil {
		log.Fatal(err)
	}
	app, err := newApp(c, secrets, store)
	if err != nil {
		log.Fatal("cannot initialize application; check the local key and templates")
	}
	server := &http.Server{
		Addr: c.ListenAddr, Handler: app.handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second,
		WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32768,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		// Allow an in-flight refresh (20 seconds) to save its rotated token pair.
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("Open %s — OAuth configured: %t", c.PublicBaseURL, app.configured)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("cannot start HTTP server; check whether the listen port is already in use")
	}
	<-done
}
