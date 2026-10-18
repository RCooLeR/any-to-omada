// Command any-to-omada runs the independent experimental camera translator.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/RCooLeR/any-to-omada/internal/app"
	"github.com/RCooLeR/any-to-omada/internal/config"
)

func main() {
	if err := execute(os.Args[1:]); err != nil {
		slog.Error("translator command failed", "error", err)
		os.Exit(1)
	}
}

func execute(args []string) error {
	if len(args) == 0 {
		return errors.New("use serve, check, healthcheck or version")
	}
	if args[0] == "version" {
		fmt.Println(app.Version)
		return nil
	}
	if args[0] != "serve" && args[0] != "check" && args[0] != "healthcheck" {
		return errors.New("unknown command")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "/config/config.json", "configuration path")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("invalid command arguments")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if args[0] == "check" {
		fmt.Println("configuration valid; credentials, network and native Omada acceptance have not been tested")
		return nil
	}
	if args[0] == "healthcheck" {
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+cfg.ControlAddress+"/healthz", nil)
		if err != nil {
			return errors.New("healthcheck configuration invalid")
		}
		response, err := client.Do(request)
		if err != nil {
			return errors.New("translator healthcheck failed")
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return errors.New("translator healthcheck failed")
		}
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, cfg, slog.New(slog.NewJSONHandler(os.Stderr, nil)))
}
