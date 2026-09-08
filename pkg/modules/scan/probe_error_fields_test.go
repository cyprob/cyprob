package scan

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The registry guard in probe_error_codes_test.go walks what a classifier
// returns. This one walks what is written into the field the result reports,
// which is not the same set -- and the difference is the point.
//
// Measured on this package: 27 classifiers return registry constants and
// nothing else, while the reported field is *also* written by bare literals no
// classifier produces (`enum_failed`, `identify_failed`, `no_candidate`), by
// fmt.Sprintf (`status_404`), and by raw Go error text (`err.Error()`). Two of
// those literals are already ranked by a priority table, so they are live, not
// leftovers.
//
// This matters beyond tidiness. cyprob/cyprob-ee#461 stores the reported value
// as `reason` and derives `outcome` from it. A value that is not a registry
// code derives no bucket -- by design, it lands as a NULL-outcome row rather
// than a wrong one -- but `err.Error()` is worse than unmapped: it puts
// unbounded text into a column meant to hold a vocabulary of 49.
//
// So this test does not fix any of that. It makes the set enumerable and stops
// it growing: every write that is not a registry code has to be named below,
// with what it would take to resolve it. The list is the work queue.
//
// One blindness was found while building it and is worth stating, because the
// same mistake is easy to repeat: an earlier version walked assignments only.
// It reported the FTP probe clean. FTP writes its code through a composite
// literal (`FTPProbeAttempt{Error: code}`) from a local that is assigned from a
// classifier on four paths and from the literal "feat_failed" on a fifth. A
// walk that does not follow composite literals and locals sees a classifier
// call and agrees.

// reportedErrorFields are the fields a probe result reports its failure in.
var reportedErrorFields = map[string]bool{
	"ProbeError": true,
	"ErrorClass": true,
	"Error":      true,
}

// reportedFieldWritesOutsideTheRegistry is every write to those fields that is
// not a registry code, with what it needs. A write is a failure by default;
// appearing here is a statement, not a silence.
//
// Keys are "<enclosing function>: <what was written>", which survives the lines
// moving. Values say what would resolve it -- promote the value to a registry
// code with an outcome entry, or route it through the classifier that should
// have produced it.
var reportedFieldWritesOutsideTheRegistry = map[string]string{
	// Bare literals. Each is a code in everything but name: short, stable, and
	// meant to be read as a category. They need a ProbeCode constant and an
	// outcome entry, and two of them are already ranked by a priority table.
	"probeDNSDetails: literal \"no_candidate\"":                                            "no target survived candidate selection; scanner-side, so its outcome would be no-claim",
	"probeFavicon: literal \"empty_body\"":                                                 "the response arrived and its body was empty; unreadable, once it is a code",
	"probeFavicon: literal \"request_error\"":                                              "a catch-all around client.Do; would need splitting before it could carry a bucket",
	"probeIPMIDetails: literal \"dial_error\"":                                             "a dial failure IPMI spells differently from every other probe; unreachable, once unified",
	"probeIPMIDetails: literal \"invalid_port\"":                                           "our own input validation; scanner-side",
	"probeSMBDetails: literal \"enum_failed\"":                                             "the share enumeration step failed after a successful negotiate; distinct from enum_not_supported",
	"runCommandProbe: literal \"print_port_write_blocked\"":                                "a refusal to write to a printer port, which is our policy rather than the target's behavior",
	"runRedirectProbe: literal \"redirect_budget_exceeded\"":                               "our own budget; scanner-side",
	"followHTTPRedirects: literal \"redirect_budget_exceeded\"":                            "the same budget, spelled at a second site",
	"fetchSSDPDescription: literal \"description unreadable\"":                             "prose, not a code -- and the bucket whose name it contains is not the bucket it belongs to",
	"fetchSSDPDescription: literal \"description unreachable\"":                            "prose, not a code",
	"fetchSSDPDescription: literal \"description request rejected\"":                       "prose, not a code",
	"fetchSSDPDescription: literal \"description location does not belong to the target\"": "prose, and a sentence long enough to be a log line",

	// Synthesized values. Invisible to any inventory, which is exactly how
	// write_failed and read_failed stayed out of the first one.
	"probeFavicon: call fmt.Sprintf":         "builds status_404 and friends from the HTTP status; unbounded in principle, ~60 values in practice",
	"fetchSSDPDescription: call fmt.Sprintf": "builds \"description status_%d\"; the prose prefix makes it unmatchable as well as unmapped",

	// Raw Go error text. Not a vocabulary at all.
	"probeNBNSDetails: raw error text via .Error()": "writes err.Error() straight into the reported field; needs a classifier like every other probe",
	"runCommandProbe: raw error text via .Error()":  "banner_grab's observation error, which holds free text and registry codes in the same field",
	"runPassiveProbe: raw error text via .Error()":  "the same field, the same mix",

	// Values this walk cannot resolve. Each needs a reader, not a rule.
	"mapToRPCEpmapperInfo: call strings.TrimSpace": "trims a value carried from elsewhere; the source decides whether it is a code",
	"probeRPCEpmapperDetails: index":               "allErrors[0], a slice built from classifier output; provably codes, not provable here",
	"probeRPCFollowupDetails: index":               "allErrors[0], same shape",
	"probeTelnetDetails: ident errCode":            "a parameter; its caller passes classifier output",
	"runProbes: ident lastError":                   "an outer-scope variable assigned across several branches",
	"newRedirectSkipObservation: ident reason":     "a parameter; every caller passes a literal, and two of those literals are listed above",
}

func TestProbeCodes_TheReportedFieldOnlyCarriesRegistryCodes(t *testing.T) {
	t.Parallel()

	registry := map[string]bool{}
	for _, code := range probeCodeRegistry {
		registry[string(code)] = true
	}
	if len(registry) == 0 {
		t.Fatal("the registry is empty, so every write below would be rejected for the wrong reason")
	}

	seen := map[string]bool{}
	writesSeen, acceptedSeen, compositeSeen, localsResolved := 0, 0, 0, 0

	for _, file := range parseScanPackage(t) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			locals := reportedFieldLocals(fn)
			record := func(value ast.Expr, composite bool) {
				writesSeen++
				if composite {
					compositeSeen++
				}
				problems := reportedFieldProblems(value, registry, locals, 0, &localsResolved)
				if len(problems) == 0 {
					acceptedSeen++
					return
				}
				for _, problem := range problems {
					key := fn.Name.Name + ": " + problem
					seen[key] = true
					reason, listed := reportedFieldWritesOutsideTheRegistry[key]
					if !listed {
						t.Errorf("%s writes %s into %s, which is not a registry code.\n"+
							"Every value the result reports has to be one, or be named in "+
							"reportedFieldWritesOutsideTheRegistry with what it needs -- "+
							"otherwise EE stores a reason nothing can bucket and nobody can count.",
							fn.Name.Name, problem, "the reported error field")
						continue
					}
					if strings.TrimSpace(reason) == "" {
						t.Errorf("%q is listed with no reason, which is how an exclusion outlives the thing it excused", key)
					}
				}
			}

			ast.Inspect(fn.Body, func(node ast.Node) bool {
				switch n := node.(type) {
				case *ast.CompositeLit:
					for _, elt := range n.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if key, ok := kv.Key.(*ast.Ident); ok && reportedErrorFields[key.Name] {
							record(kv.Value, true)
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range n.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok || !reportedErrorFields[sel.Sel.Name] || i >= len(n.Rhs) {
							continue
						}
						record(n.Rhs[i], false)
					}
				}
				return true
			})
		}
	}

	// Counters, for the reason the registry guard already states: a walk that
	// inspects nothing finds nothing and reports success.
	if writesSeen == 0 {
		t.Error("no write to a reported error field was found, so this test asserts nothing")
	}
	if acceptedSeen == 0 {
		t.Error("no write was accepted; the walk is looking at the wrong thing and would agree with anything")
	}
	if compositeSeen == 0 {
		t.Error("no composite literal was inspected -- the FTP codes are written that way, and an assignment-only walk calls them clean")
	}
	if localsResolved == 0 {
		t.Error("no local was resolved through to its assignments, which is the step that sees string(code) for what it is")
	}

	stale := make([]string, 0)
	for key := range reportedFieldWritesOutsideTheRegistry {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("these writes are listed and no longer exist: %v\n"+
			"A list that still excuses something gone is a list nobody trusts.", stale)
	}
	t.Logf("%d writes to reported error fields: %d carry registry codes, %d are listed exceptions (%d composite literals, %d locals resolved)",
		writesSeen, acceptedSeen, len(seen), compositeSeen, localsResolved)
}

// reportedFieldProblems returns one short, stable description per reason this
// expression is not a registry code, and nothing at all when it is.
func reportedFieldProblems(expr ast.Expr, registry map[string]bool, locals map[string][]ast.Expr, depth int, localsResolved *int) []string {
	if depth > 4 {
		return []string{"unresolved: nested too deeply"}
	}
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return []string{"non-string literal"}
		}
		value, err := strconv.Unquote(e.Value)
		if err != nil {
			return []string{"unparsable literal"}
		}
		// "" is the absence of a code, not a code.
		if value == "" || registry[value] {
			return nil
		}
		return []string{fmt.Sprintf("literal %q", value)}
	case *ast.Ident:
		if registry[probeCodeConstantValue(e.Name)] {
			return nil
		}
		assigned, ok := locals[e.Name]
		if !ok {
			return []string{"ident " + e.Name}
		}
		*localsResolved++
		problems := make([]string, 0)
		seen := map[string]bool{}
		for _, value := range assigned {
			for _, problem := range reportedFieldProblems(value, registry, locals, depth+1, localsResolved) {
				if !seen[problem] {
					seen[problem] = true
					problems = append(problems, problem)
				}
			}
		}
		sort.Strings(problems)
		return problems
	case *ast.SelectorExpr:
		// Copying a field that this same test governs. x.ProbeError =
		// y.ProbeError propagates a value already checked at its source.
		if reportedErrorFields[e.Sel.Name] {
			return nil
		}
		return []string{"selector ." + e.Sel.Name}
	case *ast.IndexExpr:
		return []string{"index"}
	case *ast.CallExpr:
		switch fun := e.Fun.(type) {
		case *ast.Ident:
			if fun.Name == "string" && len(e.Args) == 1 {
				return reportedFieldProblems(e.Args[0], registry, locals, depth+1, localsResolved)
			}
			if strings.HasPrefix(fun.Name, "classify") || strings.HasPrefix(fun.Name, "pickTop") {
				return nil
			}
			return []string{"call " + fun.Name}
		case *ast.SelectorExpr:
			// err.Error(), ctxErr.Error(), readErr.Error(): raw Go error text.
			// The receiver's name is incidental -- what matters is that the
			// value has no vocabulary at all, so they collapse to one problem.
			if fun.Sel.Name == "Error" && len(e.Args) == 0 {
				return []string{"raw error text via .Error()"}
			}
			if pkg, ok := fun.X.(*ast.Ident); ok {
				return []string{"call " + pkg.Name + "." + fun.Sel.Name}
			}
			return []string{"call ." + fun.Sel.Name}
		}
	}
	return []string{fmt.Sprintf("unresolved %T", expr)}
}

// reportedFieldLocals collects every assignment to a plain identifier in a
// function, so a code written as string(code) can be followed to what code
// actually holds -- on every path, not the first one.
func reportedFieldLocals(fn *ast.FuncDecl) map[string][]ast.Expr {
	locals := map[string][]ast.Expr{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
				locals[ident.Name] = append(locals[ident.Name], assign.Rhs[i])
			}
		}
		return true
	})
	return locals
}
