// Package cli implements the mcpeel command and its bounded scan scheduler.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/st3fan/mcpeel/internal/probe"
	"github.com/st3fan/mcpeel/internal/targets"
)

type stringsFlag []string

func (s *stringsFlag) String() string { return fmt.Sprint([]string(*s)) }
func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type config struct {
	targets     stringsFlag
	list        string
	concurrency int
	timeout     time.Duration
	noSubdomain bool
	json        bool
	verbose     bool
}

// Run returns a process exit code. Probe failures are ordinary scan results;
// usage, input-source and output failures are command failures.
func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	var cfg config
	flags := flag.NewFlagSet("mcpeel", flag.ContinueOnError)
	flags.SetOutput(errOut)
	flags.Var(&cfg.targets, "u", "target host or HTTP(S) URL (repeatable)")
	flags.Var(&cfg.targets, "target", "alias for -u")
	flags.StringVar(&cfg.list, "l", "", "newline-delimited host file (- for stdin)")
	flags.StringVar(&cfg.list, "list", "", "alias for -l")
	flags.IntVar(&cfg.concurrency, "c", 10, "maximum concurrent candidate exchanges")
	flags.DurationVar(&cfg.timeout, "timeout", 2500*time.Millisecond, "deadline per target endpoint (e.g. 2.5s)")
	flags.BoolVar(&cfg.noSubdomain, "no-subdomain", false, "disable mcp. hostname expansion")
	flags.BoolVar(&cfg.json, "j", false, "write confirmed findings as JSON Lines")
	flags.BoolVar(&cfg.json, "json", false, "write confirmed findings as JSON Lines")
	flags.BoolVar(&cfg.verbose, "v", false, "write unconfirmed candidate diagnostics to stderr")
	flags.Usage = func() {
		fmt.Fprintln(errOut, "Usage: mcpeel [-u host] [-l hosts.txt] [options]\n       cat hosts.txt | mcpeel\n\nDiscover MCP servers on supplied hosts and their mcp. hostnames.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || cfg.concurrency < 1 || cfg.timeout <= 0 {
		fmt.Fprintln(errOut, "mcpeel: use -u for targets; -c and -timeout must be positive")
		return 2
	}
	cs, diagnostics, err := load(ctx, cfg, in)
	for _, diagnostic := range diagnostics {
		fmt.Fprintln(errOut, "mcpeel:", diagnostic)
	}
	if ctx.Err() != nil {
		return 130
	}
	if err != nil {
		fmt.Fprintln(errOut, "mcpeel:", err)
		return 1
	}
	if len(cs) == 0 {
		flags.Usage()
		return 1
	}
	p := probe.New(cfg.timeout)
	defer p.Close()
	if err := scan(ctx, cfg, cs, p, out, errOut); err != nil {
		if ctx.Err() != nil {
			return 130
		}
		fmt.Fprintln(errOut, "mcpeel:", err)
		return 1
	}
	return 0
}

func interactive(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	stat, err := f.Stat()
	return err == nil && stat.Mode()&os.ModeCharDevice != 0
}

// Collect before dispatch so overlapping inputs can merge fallback permission
// without probing the same URL twice. HTTP results still stream as workers finish.
func load(ctx context.Context, cfg config, in io.Reader) ([]targets.Candidate, []error, error) {
	var candidates []targets.Candidate
	var diagnostics []error
	seen := make(map[string]int)
	add := func(line string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		t, err := targets.Parse(line)
		if err != nil {
			diagnostics = append(diagnostics, fmt.Errorf("invalid target %q: %w", line, err))
			return nil
		}
		for _, c := range targets.Candidates(t, !cfg.noSubdomain) {
			if index, ok := seen[c.URL]; ok {
				if c.Fallback && !candidates[index].Fallback {
					// Attribute any fallback to the schemeless input authorizing it.
					candidates[index] = c
				}
				continue
			}
			seen[c.URL] = len(candidates)
			candidates = append(candidates, c)
		}
		return nil
	}
	for _, input := range cfg.targets {
		if err := targets.ReadLines(strings.NewReader(input), add); err != nil {
			return candidates, diagnostics, err
		}
	}
	if cfg.list != "" && cfg.list != "-" {
		f, err := os.Open(cfg.list)
		if err != nil {
			return candidates, diagnostics, err
		}
		err = targets.ReadLines(f, add)
		f.Close()
		if err != nil {
			return candidates, diagnostics, fmt.Errorf("read %s: %w", cfg.list, err)
		}
	}
	if cfg.list == "-" || !interactive(in) {
		if err := targets.ReadLines(in, add); err != nil {
			return candidates, diagnostics, fmt.Errorf("read stdin: %w", err)
		}
	}
	return candidates, diagnostics, nil
}

type checker interface {
	Probe(context.Context, targets.Candidate) (*probe.Finding, error)
}

type result struct {
	candidate targets.Candidate
	finding   *probe.Finding
	err       error
}

func scan(parent context.Context, cfg config, cs []targets.Candidate, p checker, out, errOut io.Writer) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	workers := min(cfg.concurrency, len(cs))
	jobs := make(chan targets.Candidate)
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case c, ok := <-jobs:
					if !ok {
						return
					}
					f, err := p.Probe(ctx, c)
					select {
					case results <- result{c, f, err}:
					case <-ctx.Done():
						return
					}
				}
			}
		})
	}
	go func() {
		defer close(jobs)
		for _, c := range cs {
			select {
			case jobs <- c:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	seen := make(map[string]bool)
	var writeErr error
	for r := range results {
		if r.err != nil && cfg.verbose {
			fmt.Fprintf(errOut, "mcpeel: %s: %v\n", r.candidate.URL, r.err)
		}
		if r.finding == nil || seen[r.finding.URL] || writeErr != nil || ctx.Err() != nil {
			continue
		}
		seen[r.finding.URL] = true
		if cfg.json {
			writeErr = encoder.Encode(r.finding)
		} else {
			_, writeErr = fmt.Fprintln(out, r.finding.URL)
		}
		if writeErr != nil {
			cancel()
		}
	}
	if writeErr != nil {
		return fmt.Errorf("write findings: %w", writeErr)
	}
	return parent.Err()
}
