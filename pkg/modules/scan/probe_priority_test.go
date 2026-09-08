package scan

import (
	"go/ast"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// A priority table decides which of several attempt codes becomes the service's
// answer, and a code the table does not name loses to every code it does.
//
// That makes the table a second place the vocabulary has to be right, and a
// quiet one: nothing fails when a code is missing, the answer just changes.
// cyprob#344 is the measured case -- it split netbios_session_rejected and
// unknown_smb_signature out of probe_failed precisely so the catch-all would
// stop hiding them, and pickTopProbeError went on ranking probe_failed and not
// them, handing the catch-all the answer back one function later.
//
// So: every code a protocol's classifiers can return must be ranked by that
// protocol's table.

// probePriorityTables maps a priority table to the classifiers whose output it
// ranks. A table missing from here is not checked, so the map is the thing to
// extend when one is added.
var probePriorityTables = map[string][]string{
	"pickTopProbeError":       {"classifySMBProbeError"},
	"sshProbeErrorPriority":   {"classifySSHProbeError"},
	"smtpProbeErrorPriority":  {"classifySMTPProbeError"},
	"mysqlProbeErrorPriority": {"classifyMySQLConnectError", "classifyMySQLReadError", "classifyMySQLTLSError"},
	"pickTopTLSProbeError":    {"classifyTLSProbeError"},
	"pickTopRDPProbeError":    {"classifyRDPProbeError"},
	"pickTopRedisError":       {"classifyRedisError"},
	"pickTopPostgresError":    {"classifyPostgresError"},
	"pickTopSNMPProbeError":   {"classifySNMPProbeError"},

	// FTP names three of its five classifiers on purpose. classifyFTPFeatError
	// and classifyFTPSystError produce feat_failed and syst_failed, and those
	// two codes cannot reach this table: they enter attemptErrors alone, and
	// pickTopFTPPartialError filters that list to six codes which do not include
	// them (cyprob#362). Listing them here would demand the table rank codes it
	// can never be handed.
	//
	// So this pairing is the check that keeps the deletion honest in both
	// directions: re-rank one of them and "ranks codes its classifiers can no
	// longer produce" fires; route one into the picker without ranking it and
	// the other half fires once its classifier is added here.
	"ftpProbeErrorPriority": {"classifyFTPConnectError", "classifyFTPBannerError", "classifyFTPTLSError"},
}

// probePriorityTablesRankingUnregisteredValues are tables that rank a value CE
// does not register, with why. Each is a code path living outside the registry:
// the value is produced, reaches the table, and can win -- it simply has no
// constant.
// probePriorityTablesRankingUnregisteredValues are tables that rank a value CE
// does not register, with why.
//
// Empty since cyprob#339: ftpProbeErrorPriority and winrmProbeErrorPriority were
// here for feat_failed, syst_failed and identify_failed, and those are registry
// codes now. The map stays because the check it feeds is the one that would
// notice the next such value, and an empty exemption list is the honest state of
// a rule nothing currently breaks.
var probePriorityTablesRankingUnregisteredValues = map[string]string{}

func TestProbePriority_EveryProducibleCodeIsRanked(t *testing.T) {
	t.Parallel()

	files := parseScanPackage(t)
	registry := map[string]bool{}
	for _, code := range probeCodeRegistry {
		registry[string(code)] = true
	}

	checked, rankedSeen := 0, 0
	for table, classifiers := range probePriorityTables {
		produced := map[string]bool{}
		for _, classifier := range classifiers {
			for _, code := range constantsReturnedBy(files, classifier) {
				produced[code] = true
			}
		}
		if len(produced) == 0 {
			t.Errorf("%s: its classifiers return no registry constant, so this pair checks nothing", table)
			continue
		}

		ranked := valuesNamedIn(files, table, registry)
		if len(ranked) == 0 {
			t.Errorf("%s: no code was found in the table; the walk is looking at the wrong thing", table)
			continue
		}
		checked++
		rankedSeen += len(ranked)

		missing := make([]string, 0)
		for code := range produced {
			if !ranked[code] {
				missing = append(missing, code)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s does not rank codes its classifiers can produce: %v.\n"+
				"An unranked code loses to every ranked one, so the answer changes and nothing fails.",
				table, missing)
		}

		// The other direction, and the one the first version of this test
		// missed. A code removed from a classifier but left in the table is
		// invisible to the check above: the produced set shrinks, nothing is
		// reported missing, and the table quietly ranks something that can no
		// longer arrive. That is the same shape as every other check tonight
		// that went quiet when its subject disappeared.
		//
		// Stale entries are not harmful on their own -- a rank for a code that
		// never arrives never fires -- but they are the record of what this
		// protocol can say, and a wrong record is read as a right one.
		stale := make([]string, 0)
		for code := range ranked {
			if !produced[code] {
				stale = append(stale, code)
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s ranks codes its classifiers can no longer produce: %v.\n"+
				"Either a classifier stopped emitting one, or this pairing names too few classifiers.",
				table, stale)
		}
	}

	if checked == 0 {
		t.Error("no table was checked, so this test asserts nothing")
	}
	if rankedSeen == 0 {
		t.Error("no ranked code was found anywhere; a check that sees nothing agrees with everything")
	}
	t.Logf("%d tables checked, %d ranked codes seen, %d tables excused", checked, rankedSeen,
		len(probePriorityTablesRankingUnregisteredValues))
}

// The other direction: a table must not rank a value the registry does not know.
func TestProbePriority_NoTableRanksAnUnregisteredValue(t *testing.T) {
	t.Parallel()

	files := parseScanPackage(t)
	registry := map[string]bool{}
	for _, code := range probeCodeRegistry {
		registry[string(code)] = true
	}

	tables := allPriorityTables(files)
	if len(tables) == 0 {
		t.Fatal("no priority table was found, so this test asserts nothing")
	}

	seen := map[string]bool{}
	for _, table := range tables {
		unregistered := unregisteredValuesIn(files, table, registry)
		if len(unregistered) == 0 {
			continue
		}
		seen[table] = true
		reason, excused := probePriorityTablesRankingUnregisteredValues[table]
		if !excused {
			t.Errorf("%s ranks values CE does not register: %v.\n"+
				"A table that ranks a code no constant names is a code path outside the registry.",
				table, unregistered)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%s is excused with no reason", table)
		}
	}

	stale := make([]string, 0)
	for table := range probePriorityTablesRankingUnregisteredValues {
		if !seen[table] {
			stale = append(stale, table)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("these tables are excused and no longer rank an unregistered value: %v", stale)
	}
}

func constantsReturnedBy(files []*ast.File, fnName string) []string {
	codes := make([]string, 0, 8)
	forEachFunc(files, fnName, func(fn *ast.FuncDecl) {
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			ret, ok := node.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, result := range ret.Results {
				ident, ok := result.(*ast.Ident)
				if !ok {
					continue
				}
				if value := probeCodeConstantValue(ident.Name); value != "" {
					codes = append(codes, value)
				}
			}
			return true
		})
	})
	return codes
}

// valuesNamedIn collects the registry codes a table names, whether written as a
// literal or as string(ProbeCodeX).
func valuesNamedIn(files []*ast.File, fnName string, registry map[string]bool) map[string]bool {
	named := map[string]bool{}
	forEachFunc(files, fnName, func(fn *ast.FuncDecl) {
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.BasicLit:
				if n.Kind == token.STRING {
					if value, err := strconv.Unquote(n.Value); err == nil && registry[value] {
						named[value] = true
					}
				}
			case *ast.Ident:
				if value := probeCodeConstantValue(n.Name); value != "" {
					named[value] = true
				}
			}
			return true
		})
	})
	return named
}

func unregisteredValuesIn(files []*ast.File, fnName string, registry map[string]bool) []string {
	values := make([]string, 0)
	forEachFunc(files, fnName, func(fn *ast.FuncDecl) {
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil || value == "" || registry[value] {
				return true
			}
			values = append(values, value)
			return true
		})
	})
	sort.Strings(values)
	return values
}

// allPriorityTables finds the functions that rank codes, by name: pickTop*,
// *Priority. Named rather than derived, and that is a limit worth stating -- a
// table called something else is invisible here, the same blind spot
// cyprob-ee#486's enrichment gate carries.
func allPriorityTables(files []*ast.File) []string {
	names := make([]string, 0, 16)
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			name := fn.Name.Name
			if strings.HasPrefix(name, "pickTop") || strings.HasSuffix(name, "Priority") {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

func forEachFunc(files []*ast.File, fnName string, visit func(*ast.FuncDecl)) {
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name != fnName {
				continue
			}
			visit(fn)
		}
	}
}
