package adminui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/*
var assetsFS embed.FS

const (
	cspHeader = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)

func Handler() http.Handler {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		panic(err)
	}
	fileServer := http.StripPrefix("/ui/", http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", cspHeader)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		fileServer.ServeHTTP(w, r)
	})
}
