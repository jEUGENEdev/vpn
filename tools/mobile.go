//go:build tools

package tools

// Keep the binding runtime in the module graph used by gomobile bind.
import _ "golang.org/x/mobile/bind"
