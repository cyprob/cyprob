package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLookupSNMPEnterprise(t *testing.T) {
	cases := []struct {
		name       string
		oid        string
		wantVendor string
		wantOK     bool
	}{
		{"fortinet with leading dot", ".1.3.6.1.4.1.12356.101.1.1", "Fortinet", true},
		{"fortinet without leading dot", "1.3.6.1.4.1.12356.101.1", "Fortinet", true},
		{"palo alto", ".1.3.6.1.4.1.25461.2.3.18", "Palo Alto Networks", true},
		{"f5", ".1.3.6.1.4.1.3375.2.1.3.4.43", "F5 Networks", true},
		{"juniper", ".1.3.6.1.4.1.2636.1.1.1.2.10", "Juniper Networks", true},
		{"hp printer", ".1.3.6.1.4.1.11.2.3.9.1", "Hewlett-Packard", true},
		{"lexmark", ".1.3.6.1.4.1.641.2", "Lexmark", true},
		{"apc ups", ".1.3.6.1.4.1.318.1.3.27", "APC", true},
		{"unknown enterprise number", ".1.3.6.1.4.1.9999999.1", "", false},
		{"not an enterprise oid", ".1.3.6.1.2.1.1.1.0", "", false},
		{"empty", "", "", false},
		{"garbage", "not-an-oid", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vendor, product, ok := lookupSNMPEnterprise(tc.oid)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantVendor, vendor)
			if ok {
				require.NotEmpty(t, product)
			}
		})
	}
}

// TestInferSNMPHints_PENFallback verifies that inferSNMPHints now recognizes a
// vendor from the enterprise number when no specific descr pattern matches.
func TestInferSNMPHints_PENFallback(t *testing.T) {
	t.Run("fortinet via enterprise number, no descr match", func(t *testing.T) {
		vendor, product, version := inferSNMPHints("FortiGate-100F", ".1.3.6.1.4.1.12356.101.1.1000")
		require.Equal(t, "Fortinet", vendor)
		require.Equal(t, "Fortinet", product)
		require.Empty(t, version)
	})

	t.Run("specific Cisco pattern still wins over generic PEN", func(t *testing.T) {
		vendor, product, version := inferSNMPHints(
			"Cisco IOS Software, Version 15.2(4)M", ".1.3.6.1.4.1.9.1.1208")
		require.Equal(t, "Cisco", vendor)
		require.Equal(t, "Cisco IOS", product) // not the generic "Cisco" from the PEN table
		require.Equal(t, "15.2(4)M", version)
	})

	t.Run("unknown vendor stays empty", func(t *testing.T) {
		vendor, product, version := inferSNMPHints("mystery device", ".1.3.6.1.4.1.9999999.1")
		require.Empty(t, vendor)
		require.Empty(t, product)
		require.Empty(t, version)
	})
}
