package wgnet

import "fmt"

// closeError runs a cleanup function and labels its failure, so a close error
// that reaches a caller says which resource failed to close.
func closeError(context string, closeFn func() error) error {
	if err := closeFn(); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}
