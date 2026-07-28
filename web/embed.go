package web

import "embed"

// Files contains the server-rendered pages and their assets.
//
//go:embed templates/*.html static/*
var Files embed.FS
