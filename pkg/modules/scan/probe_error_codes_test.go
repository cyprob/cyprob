package scan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// cyprob-ee#461 needs every probe error code in one place, and "one place" is a
// claim that decays the moment somebody writes a literal instead. These tests
// hold it.
//
// The vocabulary was not enumerable before this, in three separate ways, and all
// three were found by measurement rather than by reading:
//
//  1. A walk over returned string literals reported 46 codes and missed
//     cert_parse_failed, because that one was already a named constant.
//  2. The same walk saw classify* functions that classify device classes and
//     record bytes rather than errors, and counted their values as codes.
//  3. classifyRawTransportError built two of its codes by concatenation --
//     stage + "_failed" -- so write_failed and read_failed existed in
//     production and in no inventory at all.
//
// The count after all three: 49.

// classifiersOutsideTheRegistry are the classify* functions that do not produce
// probe error codes, each with the reason. A function is included in the check
// by default; being outside it has to be stated, here, next to why.
//
// The default is what matters. A new classify* function is checked unless
// somebody writes a line saying otherwise, so the failure mode is a build
// failure rather than a code nobody can see.
var classifiersOutsideTheRegistry = map[string]string{
	"classifyFirstRecordByte":      "returns rawFlightKind: whether the peer speaks TLS at all, not why a probe failed",
	"classifyRawAlert":             "returns rawFlightKind: what a TLS alert byte means",
	"classifyHTTPProbeObservation": "returns nothing; it annotates an observation in place",
	"classifySNMPDevice":           "returns a device class - printer, firewall - which is an answer about the target rather than about the attempt",
}

func TestProbeCodes_EveryClassifierUsesTheRegistry(t *testing.T) {
	t.Parallel()

	registry := map[string]bool{}
	for _, code := range probeCodeRegistry {
		registry[string(code)] = true
	}
	require := func(cond bool, format string, args ...any) {
		t.Helper()
		if !cond {
			t.Errorf(format, args...)
		}
	}
	require(len(registry) > 0, "the registry is empty, so this test asserts nothing")

	checked, excluded := 0, 0
	// A walk that inspects nothing finds no literals and reports success. These
	// two count what it actually saw, so gutting the inspection fails instead of
	// passing quietly -- which it did, on the first version of this test.
	returnsSeen, registryReturnsSeen := 0, 0
	for _, file := range parseScanPackage(t) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "classify") {
				continue
			}

			if reason, outside := classifiersOutsideTheRegistry[fn.Name.Name]; outside {
				excluded++
				require(strings.TrimSpace(reason) != "",
					"%s is excluded with no reason, which is how an exclusion outlives the thing it excused",
					fn.Name.Name)
				continue
			}

			checked++
			// A literal here is a code that exists outside the registry, which
			// is the thing this file removes. Returning "" is allowed: it is
			// the absence of a code, not a code.
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				ret, ok := node.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				returnsSeen++
				for _, result := range ret.Results {
					if ident, ok := result.(*ast.Ident); ok {
						if registry[probeCodeConstantValue(ident.Name)] {
							registryReturnsSeen++
							continue
						}
						// A constant outside the registry is the same defect
						// as a literal and harder to see: this is exactly how
						// cert_parse_failed lived outside the registry while
						// being returned, and the first version of this test
						// looked only for literals and did not notice. There is
						// no exception for a named identifier -- every
						// classifier here returns ProbeCode, so nothing but a
						// registry constant can legitimately appear.
						require(false,
							"%s returns %s, which is not a probeCodeRegistry constant; "+
								"a code named somewhere else is a code nothing can enumerate",
							fn.Name.Name, ident.Name)
						continue
					}
					lit, ok := result.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil || value == "" {
						continue
					}
					require(false,
						"%s returns the literal %q; every code belongs in probeCodeRegistry, "+
							"or nothing can enumerate, map or check it",
						fn.Name.Name, value)
				}
				return true
			})
		}
	}

	require(checked > 0, "no classifier was checked, so this test asserts nothing")
	require(returnsSeen > 0, "the walk inspected no return statement, so it could not have found a literal")
	require(registryReturnsSeen > 0,
		"the walk saw no return of a registry constant; it is looking at the wrong thing, "+
			"and a check that sees nothing agrees with everything")
	require(excluded == len(classifiersOutsideTheRegistry),
		"the exclusion list names %d functions and %d were found; a name that no longer exists "+
			"stops excusing anything and starts hiding that the list is stale",
		len(classifiersOutsideTheRegistry), excluded)
	t.Logf("%d classifiers checked, %d excluded by name", checked, excluded)
}

// The registry is a list, and a list can hold the same thing twice or hold
// something no constant names.
func TestProbeCodes_TheRegistryIsConsistent(t *testing.T) {
	t.Parallel()

	seen := map[ProbeCode]bool{}
	for _, code := range probeCodeRegistry {
		if seen[code] {
			t.Errorf("%q appears in the registry twice", code)
		}
		seen[code] = true
		if strings.TrimSpace(string(code)) == "" {
			t.Error("the registry holds an empty code")
		}
	}
	if len(seen) == 0 {
		t.Fatal("the registry is empty")
	}

	// Every declared constant is in the list. A constant nobody registered is
	// invisible to anything that walks the registry, which is the whole point.
	declared := declaredProbeCodeValues(t)
	if len(declared) == 0 {
		t.Fatal("no ProbeCode constant was found in the source, so this compares nothing")
	}
	for _, value := range declared {
		if !seen[ProbeCode(value)] {
			t.Errorf("the constant for %q is declared and not in probeCodeRegistry", value)
		}
	}

	missing := make([]string, 0)
	for code := range seen {
		found := false
		for _, value := range declared {
			if value == string(code) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, string(code))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the registry holds values no constant declares: %v", missing)
	}
	t.Logf("%d codes, declared and registered", len(seen))
}

// declaredProbeCodeValues reads the ProbeCode constants out of the source rather
// than out of the registry, so the two can disagree and be caught.
func declaredProbeCodeValues(t *testing.T) []string {
	t.Helper()

	values := make([]string, 0, 64)
	for _, file := range parseScanPackage(t) {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || value.Type == nil {
					continue
				}
				ident, ok := value.Type.(*ast.Ident)
				if !ok || ident.Name != "ProbeCode" {
					continue
				}
				for _, expr := range value.Values {
					if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if unquoted, err := strconv.Unquote(lit.Value); err == nil {
							values = append(values, unquoted)
						}
					}
				}
			}
		}
	}
	sort.Strings(values)
	return values
}

// probeCodeConstantValue maps a ProbeCode constant's identifier back to its
// value, so the walk can tell "returns a registry constant" from "returns some
// other identifier" without a second hand-maintained list.
func probeCodeConstantValue(name string) string {
	for _, code := range probeCodeRegistry {
		if probeCodeIdent(code) == name {
			return string(code)
		}
	}
	return ""
}

// probeCodeIdent rebuilds the constant name from the code, the same way the
// constants are written: ProbeCode + the code in CamelCase, with the
// initialisms Go style requires.
func probeCodeIdent(code ProbeCode) string {
	initialisms := map[string]string{
		"tls": "TLS", "smb2": "SMB2", "http": "HTTP", "dns": "DNS",
		"ntlm": "NTLM", "rpc": "RPC", "eof": "EOF", "kex": "KEX",
	}
	name := "ProbeCode"
	for _, part := range strings.Split(string(code), "_") {
		if replacement, ok := initialisms[part]; ok {
			name += replacement
			continue
		}
		if part == "" {
			continue
		}
		name += strings.ToUpper(part[:1]) + part[1:]
	}
	return name
}

func parseScanPackage(t *testing.T) []*ast.File {
	t.Helper()

	fset := token.NewFileSet()
	packages, err := parser.ParseDir(fset, ".", func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package source: %v", err)
	}

	files := make([]*ast.File, 0, 64)
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			files = append(files, file)
		}
	}
	if len(files) == 0 {
		t.Fatal("no source files were parsed, so the analysis would see nothing")
	}
	return files
}
