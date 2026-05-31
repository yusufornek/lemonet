// Package web embeds the built control panel so lemonet ships as a single binary.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var assets embed.FS

// Dist returns the built panel as a filesystem rooted at the asset directory.
func Dist() fs.FS {
	sub, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
