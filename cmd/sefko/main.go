package main

import (
	"os"

	"github.com/nklmilojevic/sefko/internal/cli"
)

var version = "dev"

func main() {
	os.Exit(cli.Execute(version, os.Args[1:], cli.IO{Stdout: os.Stdout, Stderr: os.Stderr}))
}
