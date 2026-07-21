package scan

import (
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/require"
)

// Disable the live ENTITY-MIB walk for all package tests: the mock SNMP server
// only answers Get (not GetNext), so a real walk would time out and slow the
// suite. The walk-selection logic is covered directly via pickChassisModelSerial.
func init() {
	fetchSNMPEntityFunc = func(*gosnmp.GoSNMP) (string, string) { return "", "" }
}

func TestPickChassisModelSerial(t *testing.T) {
	t.Run("prefers the chassis-class entry", func(t *testing.T) {
		classes := map[string]int{"1": 10 /* module */, "2": entPhysicalClassChassis, "3": 5 /* port */}
		models := map[string]string{"1": "LineCard-X", "2": "FortiGate-100F", "3": "SFP-1G"}
		serials := map[string]string{"1": "LC123", "2": "FG100FT918", "3": "SFP999"}
		model, serial := pickChassisModelSerial(classes, models, serials)
		require.Equal(t, "FortiGate-100F", model)
		require.Equal(t, "FG100FT918", serial)
	})

	t.Run("falls back to lowest index when no chassis class", func(t *testing.T) {
		classes := map[string]int{"10": 9, "2": 9}
		models := map[string]string{"10": "ModuleB", "2": "ModuleA"}
		serials := map[string]string{"10": "B", "2": "A"}
		model, serial := pickChassisModelSerial(classes, models, serials)
		require.Equal(t, "ModuleA", model) // index 2 < 10 numerically
		require.Equal(t, "A", serial)
	})

	t.Run("skips empty rows", func(t *testing.T) {
		classes := map[string]int{"1": 9, "2": entPhysicalClassChassis}
		models := map[string]string{"2": "Catalyst-9300"}
		serials := map[string]string{"2": "CAT9300X"}
		model, serial := pickChassisModelSerial(classes, models, serials)
		require.Equal(t, "Catalyst-9300", model)
		require.Equal(t, "CAT9300X", serial)
	})

	t.Run("serial only, no model", func(t *testing.T) {
		model, serial := pickChassisModelSerial(
			map[string]int{"1": entPhysicalClassChassis},
			map[string]string{},
			map[string]string{"1": "SN-ONLY"})
		require.Empty(t, model)
		require.Equal(t, "SN-ONLY", serial)
	})

	t.Run("no data -> empty", func(t *testing.T) {
		model, serial := pickChassisModelSerial(nil, nil, nil)
		require.Empty(t, model)
		require.Empty(t, serial)
	})
}

func TestSNMPPDUIntValue(t *testing.T) {
	got, ok := snmpPDUIntValue(gosnmp.SnmpPDU{Value: 3})
	require.True(t, ok)
	require.Equal(t, 3, got)

	_, ok = snmpPDUIntValue(gosnmp.SnmpPDU{Value: "not-an-int"})
	require.False(t, ok)
}
