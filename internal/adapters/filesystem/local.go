// Package filesystem implements the FileSystem port for the local OS filesystem.
// All paths are validated and cleaned to prevent directory traversal attacks.
package filesystem

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	pkglogger "github.com/vinaycharlie01/mcp-golangci-lint/pkg/logger"
)

// LocalFileSystem implements outbound.FileSystem for the local OS.
type LocalFileSystem struct{}

// New creates a LocalFileSystem.
func New() *LocalFileSystem { return &LocalFileSystem{} }

// ValidatePath ensures path is absolute, exists, and contains no traversal sequences.
func (l *LocalFileSystem) ValidatePath(_ context.Context, path string) error {
	if path == "" {
		return fmt.Errorf("path must not be empty")
	}
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return fmt.Errorf("path must be absolute, got: %s", path)
	}
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path traversal detected in: %s", path)
	}
	if _, err := os.Stat(cleaned); err != nil {
		return fmt.Errorf("path does not exist: %s", cleaned)
	}
	return nil
}

// IsGoRepository reports whether path contains a go.mod file.
func (l *LocalFileSystem) IsGoRepository(ctx context.Context, path string) (bool, error) {
	log := pkglogger.FromContext(ctx, slog.Default())
	gomod := filepath.Join(filepath.Clean(path), "go.mod")
	_, err := os.Stat(gomod)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		log.DebugContext(ctx, "no go.mod found", slog.String("path", path))
		return false, nil
	}
	return false, fmt.Errorf("checking go.mod in %s: %w", path, err)
}

// CreateTempWorkspace creates a temporary directory and returns a cleanup function.
func (l *LocalFileSystem) CreateTempWorkspace(_ context.Context) (string, func(), error) {
	dir, err := os.MkdirTemp("", "mcp-golangci-lint-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp workspace: %w", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// ReadFile reads and returns the contents of a file.
func (l *LocalFileSystem) ReadFile(_ context.Context, path string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}
	return data, nil
}

// FileExists reports whether path refers to an existing regular file.
func (l *LocalFileSystem) FileExists(_ context.Context, path string) (bool, error) {
	info, err := os.Stat(filepath.Clean(path))
	if err == nil {
		return info.Mode().IsRegular(), nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// FindGoFiles returns all .go files under root, excluding vendor and testdata dirs.
func (l *LocalFileSystem) FindGoFiles(_ context.Context, root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(filepath.Clean(root), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}
	return files, nil
}
