package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/st3fan/mcpeel/internal/cli"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runContext(ctx)
}

func runContext(ctx context.Context) int {
	finished := make(chan int, 1)
	// A stdin read can remain blocked even after Close on some platforms. Let the
	// process exit on cancellation while ordinary scans still finish gracefully.
	go func() {
		finished <- cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	}()
	select {
	case code := <-finished:
		return code
	case <-ctx.Done():
		return 130
	}
}
