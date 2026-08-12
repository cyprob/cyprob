package format

import "errors"

// errAlreadyReported marks an error whose message the user has already seen.
//
// The summary printers show a failure and then return it, so that the command
// exits non-zero. Without a marker the caller cannot tell that error apart from
// one nobody has printed yet, and it would be shown twice — or, if the caller
// silences printing to avoid that, cobra's own errors (an unknown flag, a wrong
// argument count) would be silenced along with it.
var errAlreadyReported = errors.New("already reported")

// reportedError carries a failure that has been shown to the user.
type reportedError struct{ cause error }

func (e reportedError) Error() string { return e.cause.Error() }

// Unwrap keeps errors.Is working through the marker, so a sentinel the caller
// matches on — plugin.ErrPartialFailure, for instance — survives being wrapped.
func (e reportedError) Unwrap() error { return e.cause }

func (e reportedError) Is(target error) bool { return target == errAlreadyReported }

// Reported marks err as handled for display: either it has been shown to the
// user, or the user asked for silence and it deliberately was not. Either way
// nobody else should print it. It returns nil for nil, so it can wrap a
// printer's result without inventing a failure.
func Reported(err error) error {
	if err == nil {
		return nil
	}
	return reportedError{cause: err}
}

// IsAlreadyReported reports whether err has already been handled for display
// and so must not be printed again.
func IsAlreadyReported(err error) bool {
	return errors.Is(err, errAlreadyReported)
}
