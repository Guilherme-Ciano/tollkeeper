//go:build unix

package app

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func (a *App) reloadLoop(ctx context.Context, path string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			a.reloadFromFile(ctx, path)
		}
	}
}
