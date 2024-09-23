package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pheelee/Cat/internal/server"
	"github.com/pheelee/Cat/pkg/cert"
)

func getEnvOrString(s string, d string) string {
	a := os.Getenv(s)
	if a == "" {
		return d
	}
	return a
}

func main() {
	var port int
	var sessionHours int
	var servercfg server.Config = server.Config{}
	flag.IntVar(&port, "port", 8090, "[optional] Listening port")
	flag.StringVar(&servercfg.StaticDir, "StaticDir", getEnvOrString("STATIC_DIR", ""), "[optional] set static dir to html/js/css files")
	flag.StringVar(&servercfg.CookieSecret, "CookieSecret", getEnvOrString("COOKIE_SECRET", ""), "[mandatory] secret string to keep cookies safe")
	flag.IntVar(&sessionHours, "SessionLifetime", 24*30, "[optional] session lifetime in hours (default 30 days)")
	flag.Parse()

	if servercfg.CookieSecret == "" {
		flag.CommandLine.Usage()
		os.Exit(0)
	}
	servercfg.SessionLifetime = time.Duration(sessionHours) * time.Hour
	crt := &cert.Certificate{Name: "cat-tokensigner"}
	err := crt.Load("./")
	if err != nil || !time.Now().Before(crt.Cert.NotAfter) {
		crt, err = cert.Generate("cat-tokensigner", "Cat", "CH", "IT", fmt.Sprintf("%dh", 24*180))
		if err != nil {
			log.Fatal(err)
		}
		if err := crt.Save("./"); err != nil {
			log.Fatal(err)
		}
	}

	sm, err := server.LoadSessionManager("./sessions.json")
	if err != nil {
		log.Fatal(err)
	}
	servercfg.SessionManager = sm

	servercfg.Certificate = crt
	routines := sync.WaitGroup{}
	shutdown := make(chan struct{})
	app := server.SetupRoutes(&servercfg, shutdown, &routines)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	srv := http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           app,
		ReadHeaderTimeout: time.Second * 60,
	}
	go func(srv *http.Server) {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println("ERROR: ", err)
		}
	}(&srv)
	log.Println("Listening on port", port)
	<-sig
	log.Println("Shutting down webserver")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer func() { cancel() }()
	if err := srv.Shutdown(ctx); err != nil {
		log.Println("ERROR: ", err)
	}
	log.Println("Stopping all goroutines and wait for them to finish")
	shutdown <- struct{}{}
	routines.Wait()
}
