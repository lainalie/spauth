//go:build linux

package main

import (
	"os"

	"golang.org/x/term"
)

var useColor = term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""

func paint(code, s string) string {
	if !useColor {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func red(s string) string  { return paint("1;31", s) }
func lime(s string) string { return paint("1;38;5;118", s) }
