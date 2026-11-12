package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Guilherme-Ciano/tollkeeper/internal/cli"
)

func main() {
	path := flag.String("config", "devissuer.yaml", "dev issuer config")
	insecure := flag.Bool("i-know-this-is-insecure", false, "allow binding a non-loopback address")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := cli.RunDevIssuer(ctx, *path, *insecure, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
