package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed client/* admin/*
var files embed.FS

func Handler(name string) http.Handler {
	sub, e := fs.Sub(files, name)
	if e != nil {
		panic(e)
	}
	return http.FileServer(http.FS(sub))
}
