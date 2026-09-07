package main

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
