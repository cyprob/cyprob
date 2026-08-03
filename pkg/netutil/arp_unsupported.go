//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package netutil

// readARPTable has no supported implementation on this platform. Callers treat
// an empty table as "no information available".
func readARPTable() []ARPEntry {
	return nil
}
