package software

import "strconv"

// errWrap builds a sentinel-wrapping error without pulling fmt in for a
// two-part concatenation. The sentinel stays reachable through errors.Is, so a
// caller can tell "this field was malformed" from "this field was absent"
// without string matching.
func errWrap(sentinel error, reason string) error {
	return &wrappedError{sentinel: sentinel, reason: reason}
}

type wrappedError struct {
	sentinel error
	reason   string
}

func (e *wrappedError) Error() string { return e.sentinel.Error() + ": " + e.reason }
func (e *wrappedError) Unwrap() error { return e.sentinel }

func itoa(n int) string { return strconv.Itoa(n) }

// describeByte renders one byte for an error message. A raw control character
// pasted into a diagnostic is unreadable and, worse, can carry terminal escape
// sequences straight into whatever displays the warning.
func describeByte(c byte) string {
	if c >= 0x20 && c < 0x7f {
		return string([]byte{c})
	}
	return "0x" + strconv.FormatUint(uint64(c), 16)
}
