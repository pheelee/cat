package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/pheelee/Cat/internal/session"
	"github.com/pheelee/Cat/internal/web"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
)

var VERSION string = "0.0.0"

func main() {
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		file = short
		return file + ":" + strconv.Itoa(line)
	}
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	logger := zerolog.New(output).With().Caller().Timestamp().Logger()

	app := cli.App{
		Name:        "cat",
		Usage:       "cloud authentication tester",
		Description: "A modern authentication testing tool.",
		Version:     VERSION,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "CookieSecret",
				Aliases:  []string{"s"},
				Usage:    "secret to encode cookies",
				EnvVars:  []string{"COOKIE_SECRET"},
				Required: true,
			},
			&cli.IntFlag{
				Name:    "Port",
				Aliases: []string{"p"},
				Usage:   "listening port",
				Value:   8090,
			},
			&cli.IntFlag{
				Name:    "SessionLifetime",
				Aliases: []string{"l"},
				Usage:   "session lifetime in hours",
				Value:   24 * 30,
			},
		},
		Action: func(ctx *cli.Context) error {
			sm, err := session.NewManager(logger, time.Duration(ctx.Int("SessionLifetime"))*time.Hour, "./session.yaml")
			if err != nil {
				return err
			}
			defer func() {
				if err := sm.OnAppShutdown(); err != nil {
					logger.Error().Err(err).Msg("failed to shutdown")
				}
			}()
			app := web.GetRouter(logger, time.Duration(ctx.Int("SessionLifetime")), sm.Middleware)
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
			srv := http.Server{
				Addr:              ":" + strconv.Itoa(ctx.Int("Port")),
				Handler:           app,
				ReadHeaderTimeout: 5 * time.Second,
			}
			go func(srv *http.Server) {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Error().Err(err).Msg("failed to listen and serve")
				}
			}(&srv)
			logger.Info().Int("port", ctx.Int("Port")).Msg("server started")
			<-sig
			logger.Info().Msg("shutting down server")
			sctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer func() { cancel() }()
			if err := srv.Shutdown(sctx); err != nil {
				return err
			}
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Error().Err(err).Msg("failed to run")
	}
}
