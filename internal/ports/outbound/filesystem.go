package outbound

import "context"

// FileSystem is the port for file system operations.
// Implementations must perform path validation to prevent directory traversal.
type FileSystem interface {
	ValidatePath(ctx context.Context, path string) error
	IsGoRepository(ctx context.Context, path string) (bool, error)
	CreateTempWorkspace(ctx context.Context) (path string, cleanup func(), err error)
	ReadFile(ctx context.Context, path string) ([]byte, error)
	FileExists(ctx context.Context, path string) (bool, error)
	FindGoFiles(ctx context.Context, root string) ([]string, error)
}
