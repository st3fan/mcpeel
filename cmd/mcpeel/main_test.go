package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"testing"
	"time"
)

// Exercise cancellation in a subprocess so stdin really is an open, stalled pipe.
func TestInterruptBlockedStdin(t *testing.T) {
	if os.Getenv("MCPEEL_TEST_BLOCKED_STDIN") == "1" {
		os.Args = []string{"mcpeel"}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		fmt.Fprintln(os.Stderr, "ready")
		os.Exit(runContext(ctx))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInterruptBlockedStdin$")
	cmd.Env = append(os.Environ(), "MCPEEL_TEST_BLOCKED_STDIN=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stderr)
	if ready, err := reader.ReadString('\n'); ready != "ready\n" || err != nil {
		cmd.Wait()
		t.Fatalf("helper did not become ready: %q, %v", ready, err)
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil || cmd.ProcessState.ExitCode() != 130 {
		t.Fatalf("expected interrupt exit 130, got %v (%v)", cmd.ProcessState, err)
	}
}
