//go:build !unix

package app

import "context"

func (a *App) reloadLoop(ctx context.Context, _ string) {
	<-ctx.Done()
}
