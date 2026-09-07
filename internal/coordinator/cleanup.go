package coordinator

import (
	"errors"
	"fmt"
)

// closeWithError joins a cleanup failure onto a function's named error return
// without discarding the primary error.
func closeWithError(errp *error, context string, closeFn func() error) {
	if err := closeFn(); err != nil {
		*errp = errors.Join(*errp, fmt.Errorf("%s: %w", context, err))
	}
}

// closeError runs a cleanup function and labels its failure.
func closeError(context string, closeFn func() error) error {
	if err := closeFn(); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}
