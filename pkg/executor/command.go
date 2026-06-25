// Package executor provides safe external command execution with context support.
// Arguments are always passed separately to exec.Command – never shell-interpolated –
// to prevent command injection.
package executor

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	pkglogger "github.com/vinaycharlie01/mcp-golangci-lint/pkg/logger"
)

// Result holds the outcome of a command execution.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// Options controls how the command is executed.
type Options struct {
	Timeout time.Duration
	Dir     string
	Env     []string
}

// Run executes name with args safely.
// A non-zero exit code is NOT returned as an error – callers inspect Result.ExitCode.
// Only context cancellation or a missing binary returns a non-nil error.
func Run(ctx context.Context, opts Options, name string, args ...string) (*Result, error) {
	log := pkglogger.FromContext(ctx, slog.Default())

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, name, args...)
	if opts.Dir != "" {
		cmd.Dir = opts.Dir
	}
	if len(opts.Env) > 0 {
		cmd.Env = opts.Env
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	log.DebugContext(ctx, "executing command",
		slog.String("command", name),
		slog.String("dir", opts.Dir),
	)

	runErr := cmd.Run()
	duration := time.Since(start)

	if runErr != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("command timed out after %s: %w", opts.Timeout, ctx.Err())
		}
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			log.DebugContext(ctx, "command exited non-zero",
				slog.String("command", name),
				slog.Int("exit_code", exitErr.ExitCode()),
				slog.Duration("duration", duration),
			)
			return &Result{
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				ExitCode: exitErr.ExitCode(),
				Duration: duration,
			}, nil
		}
		return nil, fmt.Errorf("executing %q: %w", name, runErr)
	}

	log.DebugContext(ctx, "command succeeded",
		slog.String("command", name),
		slog.Duration("duration", duration),
	)

	return &Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
		Duration: duration,
	}, nil
}
