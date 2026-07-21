package scan

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// ENTITY-MIB (RFC 4133) columns used to recover the chassis model and serial.
const (
	oidEntPhysicalClass     = ".1.3.6.1.2.1.47.1.1.1.1.5"
	oidEntPhysicalSerialNum = ".1.3.6.1.2.1.47.1.1.1.1.11"
	oidEntPhysicalModelName = ".1.3.6.1.2.1.47.1.1.1.1.13"

	entPhysicalClassChassis = 3 // per ENTITY-MIB PhysicalClass enumeration

	snmpEntityWalkMaxRows = 256
	snmpEntityWalkTimeout = 800 * time.Millisecond
)

var errStopSNMPWalk = errors.New("snmp entity walk bound reached")

// fetchSNMPEntityFunc is indirected so tests can disable the live walk.
var fetchSNMPEntityFunc = fetchSNMPEntity

// fetchSNMPEntity walks the ENTITY-MIB and returns the chassis model and serial.
// Best-effort: any error yields empty strings. It first probes entPhysicalClass;
// if the device exposes no ENTITY-MIB, it bails before the two heavier walks so
// non-ENTITY devices pay at most one short walk.
func fetchSNMPEntity(client *gosnmp.GoSNMP) (model, serial string) {
	prev := client.Timeout
	client.Timeout = snmpEntityWalkTimeout
	defer func() { client.Timeout = prev }()

	classPDUs := walkSNMPColumn(client, oidEntPhysicalClass)
	if len(classPDUs) == 0 {
		return "", ""
	}
	classes := make(map[string]int, len(classPDUs))
	for idx, pdu := range classPDUs {
		if n, ok := snmpPDUIntValue(pdu); ok {
			classes[idx] = n
		}
	}
	models := stringColumn(walkSNMPColumn(client, oidEntPhysicalModelName))
	serials := stringColumn(walkSNMPColumn(client, oidEntPhysicalSerialNum))
	return pickChassisModelSerial(classes, models, serials)
}

// walkSNMPColumn walks a single table column and returns index -> PDU, bounded
// to snmpEntityWalkMaxRows. Errors are swallowed (best-effort enrichment).
func walkSNMPColumn(client *gosnmp.GoSNMP, rootOID string) map[string]gosnmp.SnmpPDU {
	out := map[string]gosnmp.SnmpPDU{}
	root := strings.TrimPrefix(rootOID, ".")
	_ = client.Walk(rootOID, func(pdu gosnmp.SnmpPDU) error {
		if len(out) >= snmpEntityWalkMaxRows {
			return errStopSNMPWalk
		}
		name := strings.TrimPrefix(pdu.Name, ".")
		idx := strings.TrimPrefix(name, root+".")
		if idx != "" && idx != name {
			out[idx] = pdu
		}
		return nil
	})
	return out
}

func stringColumn(pdus map[string]gosnmp.SnmpPDU) map[string]string {
	out := make(map[string]string, len(pdus))
	for idx, pdu := range pdus {
		if v := strings.TrimSpace(snmpPDUStringValue(pdu)); v != "" {
			out[idx] = v
		}
	}
	return out
}

// pickChassisModelSerial selects the chassis entry's model and serial. It
// prefers the entry whose entPhysicalClass is chassis; otherwise the
// lowest-indexed entry that carries a model or serial (the chassis is typically
// the first physical entity).
func pickChassisModelSerial(classes map[string]int, models, serials map[string]string) (model, serial string) {
	indexSet := map[string]struct{}{}
	for idx := range models {
		indexSet[idx] = struct{}{}
	}
	for idx := range serials {
		indexSet[idx] = struct{}{}
	}
	indices := make([]string, 0, len(indexSet))
	for idx := range indexSet {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return snmpIndexLess(indices[i], indices[j])
	})

	chassis, first := "", ""
	for _, idx := range indices {
		if models[idx] == "" && serials[idx] == "" {
			continue
		}
		if first == "" {
			first = idx
		}
		if classes[idx] == entPhysicalClassChassis && chassis == "" {
			chassis = idx
		}
	}
	pick := chassis
	if pick == "" {
		pick = first
	}
	if pick == "" {
		return "", ""
	}
	return models[pick], serials[pick]
}

func snmpIndexLess(a, b string) bool {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	if aerr == nil && berr == nil {
		return ai < bi
	}
	return a < b
}

func snmpPDUIntValue(pdu gosnmp.SnmpPDU) (int, bool) {
	switch v := pdu.Value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint64:
		return int(v), true
	case uint32:
		return int(v), true
	default:
		return 0, false
	}
}
