package scan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
)

// cyprob#316: a module can read a config option it never declares, and nothing
// checks for it. Two instances were found by hand and fixed — smb-native-probe's
// include_enum and fallback_to_netbios (#315), and banner-grab's
// tls_insecure_skip_verify (#322) — but the issue's own title is about the
// checking, and the sweep that found them was a throwaway script.
//
// cyprob-ee has a guard of this shape already
// (TestPortScanDAG_EveryConfigKeyIsDeclaredByItsModule), but it can only see the
// keys EE *sends*. A key a module reads and nobody currently sends is invisible
// there, and this is the side that knows what is read.
//
// The check reads this package's own source: what a module reads out of its
// configMap is a property of the code, not of any value, so nothing at runtime
// can be asked for it.

// configReadingHelpers are the functions that read configMap on a module's
// behalf. Init calling one of them reads those keys as surely as if it indexed
// the map itself, so the analysis has to follow them — and this list is
// hand-maintained, which is exactly the kind of assumption that rots silently.
// helpersStillExist below fails if one is renamed away, so the guard cannot
// quietly start checking less than it claims.
var configReadingHelpers = map[string][]string{
	"initCommonTCPProbeOptions": {"timeout", "connect_timeout", "io_timeout", "retries"},
}

// configKeyArgumentHelpers read one key named by a string argument.
var configKeyArgumentHelpers = map[string]int{
	"parseOptionalPortList": 1, // parseOptionalPortList(configMap, "extra_ports")
}

func TestEveryModuleDeclaresTheConfigOptionsItReads(t *testing.T) {
	t.Parallel()

	readsByType := configKeysReadByInit(t)
	if len(readsByType) == 0 {
		t.Fatal("no Init method was analyzed, so this test asserts nothing")
	}

	checked := 0
	for name, factory := range engine.GetRegisteredModuleFactories() {
		module := factory()
		typeName := moduleTypeName(module)
		keys, analyzed := readsByType[typeName]
		if !analyzed {
			// A module registered elsewhere. Its own package is where it would
			// be checked.
			continue
		}
		checked++

		schema := module.Metadata().ConfigSchema
		for _, key := range keys {
			if _, declared := schema[key]; !declared {
				t.Errorf("%s (%s) reads %q from its config and does not declare it: "+
					"a caller can set it, and nothing reading the schema — a validator, a planner, a UI — can know it exists",
					name, typeName, key)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no registered module was matched to an analyzed Init, so this test asserts nothing")
	}
	t.Logf("checked %d modules in this package", checked)
}

// The analysis itself, pinned. Everything above passes vacuously if
// collectConfigKeys returns nothing — a schema check that reads no keys agrees
// with every schema. These three shapes are the ones the walk has to see.
func TestConfigKeyAnalysisSeesWhatItClaimsTo(t *testing.T) {
	t.Parallel()

	reads := configKeysReadByInit(t)

	for _, tc := range []struct {
		receiver string
		key      string
		why      string
	}{
		{"smbNativeProbeModule", "include_enum", "a direct configMap index"},
		{"smbNativeProbeModule", "timeout", "a key read through initCommonTCPProbeOptions"},
		{"tlsNativeProbeModule", "extra_ports", "a key named as an argument to parseOptionalPortList"},
		{"BannerGrabModule", "tls_insecure_skip_verify", "the read cyprob#322 had to add a declaration for"},
	} {
		t.Run(tc.receiver+"/"+tc.key, func(t *testing.T) {
			t.Parallel()
			keys, analyzed := reads[tc.receiver]
			if !analyzed {
				t.Fatalf("%s has no analyzed Init; the walk found nothing to check", tc.receiver)
			}
			for _, key := range keys {
				if key == tc.key {
					return
				}
			}
			t.Fatalf("the walk did not see %q on %s (%s); it saw %v", tc.key, tc.receiver, tc.why, keys)
		})
	}
}

// The guard's own assumption, asserted. If a helper is renamed and this list is
// not updated, the analysis silently stops following it and every key it reads
// becomes invisible — the test would keep passing while checking less.
func TestConfigReadingHelpersStillExist(t *testing.T) {
	t.Parallel()

	declared := declaredFunctionNames(t)
	for name := range configReadingHelpers {
		if !declared[name] {
			t.Errorf("configReadingHelpers names %q, which no longer exists in this package: "+
				"the declaration check has stopped following it", name)
		}
	}
	for name := range configKeyArgumentHelpers {
		if !declared[name] {
			t.Errorf("configKeyArgumentHelpers names %q, which no longer exists in this package", name)
		}
	}
}

func moduleTypeName(module engine.Module) string {
	value := reflect.TypeOf(module)
	for value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	return value.Name()
}

// configKeysReadByInit walks this package's source and returns, per receiver
// type, the config keys that type's Init method reads.
func configKeysReadByInit(t *testing.T) map[string][]string {
	t.Helper()

	reads := map[string]map[string]struct{}{}
	for _, file := range parsePackage(t) {
		ast.Inspect(file, func(node ast.Node) bool {
			decl, ok := node.(*ast.FuncDecl)
			if !ok || decl.Name.Name != "Init" || decl.Recv == nil || len(decl.Recv.List) == 0 {
				return true
			}
			receiver := receiverTypeName(decl.Recv.List[0].Type)
			if receiver == "" {
				return true
			}
			if _, seen := reads[receiver]; !seen {
				reads[receiver] = map[string]struct{}{}
			}
			collectConfigKeys(decl.Body, reads[receiver])
			return true
		})
	}

	out := make(map[string][]string, len(reads))
	for receiver, keys := range reads {
		list := make([]string, 0, len(keys))
		for key := range keys {
			list = append(list, key)
		}
		sort.Strings(list)
		out[receiver] = list
	}
	return out
}

func collectConfigKeys(body ast.Node, into map[string]struct{}) {
	ast.Inspect(body, func(node ast.Node) bool {
		switch expr := node.(type) {
		case *ast.IndexExpr:
			// configMap["key"]
			if ident, ok := expr.X.(*ast.Ident); ok && strings.Contains(strings.ToLower(ident.Name), "config") {
				if key, ok := stringLiteral(expr.Index); ok {
					into[key] = struct{}{}
				}
			}
		case *ast.CallExpr:
			ident, ok := expr.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			for _, key := range configReadingHelpers[ident.Name] {
				into[key] = struct{}{}
			}
			if index, wanted := configKeyArgumentHelpers[ident.Name]; wanted && index < len(expr.Args) {
				if key, ok := stringLiteral(expr.Args[index]); ok {
					into[key] = struct{}{}
				}
			}
		}
		return true
	})
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func receiverTypeName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(typed.X)
	case *ast.Ident:
		return typed.Name
	}
	return ""
}

func declaredFunctionNames(t *testing.T) map[string]bool {
	t.Helper()

	names := map[string]bool{}
	for _, file := range parsePackage(t) {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				names[fn.Name.Name] = true
			}
		}
	}
	return names
}

func parsePackage(t *testing.T) []*ast.File {
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
