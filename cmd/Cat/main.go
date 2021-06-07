package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
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
	var servercfg server.Config = server.Config{}
	flag.IntVar(&port, "port", 8090, "[optional] Listening port")
	flag.StringVar(&servercfg.StaticDir, "StaticDir", getEnvOrString("STATIC_DIR", ""), "[optional] set static dir to html/js/css files")
	flag.StringVar(&servercfg.CookieSecret, "CookieSecret", getEnvOrString("COOKIE_SECRET", ""), "[mandatory] secret string to keep cookies safe")
	flag.Parse()

	if servercfg.CookieSecret == "" {
		flag.CommandLine.Usage()
		os.Exit(0)
	}
	crt := &cert.Certificate{Name: "cat-tokensigner"}
	err := crt.Load("./")
	if err != nil || !time.Now().Before(crt.Cert.NotAfter) {
		crt, err = cert.Generate("cat-tokensigner", "Cat", "CH", "IT", fmt.Sprintf("%dh", 24*180))
		if err != nil {
			panic(err)
		}
		crt.Save("./")
	}
	servercfg.Certificate = crt
	app := server.SetupRoutes(&servercfg)

	fmt.Printf("Listening on :%d\n", port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", port), app)
	if err != nil {
		fmt.Print(err)
	}
}
