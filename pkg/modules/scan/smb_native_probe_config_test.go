package scan

import "testing"

// Both of these options are read in Init and drive real behavior -- include_enum
// gates the share and pipe enumeration, fallback_to_netbios gates the 139
// strategy -- and neither was declared in the module's schema. A caller could
// set them; anything reading the schema to find out what exists could not.
//
// The tests below check the declaration and the behavior together, because
// either alone can be right while the pair is wrong: a declared option nothing
// honors is a lie, and an honored option nothing declares is what this fixes.

func TestSMBNativeProbeModule_DeclaresTheOptionsItHonors(t *testing.T) {
	t.Parallel()

	defaults := defaultSMBProbeOptions()
	cases := []struct {
		key       string
		want      bool
		optionOf  func(SMBProbeOptions) bool
		defaultOf bool
	}{
		{"include_enum", false, func(o SMBProbeOptions) bool { return o.IncludeEnum }, defaults.IncludeEnum},
		{"fallback_to_netbios", false, func(o SMBProbeOptions) bool { return o.FallbackToNetBIOS }, defaults.FallbackToNetBIOS},
	}

	schema := newSMBNativeProbeModule().Metadata().ConfigSchema
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			t.Parallel()

			parameter, declared := schema[tc.key]
			if !declared {
				t.Fatalf("%s is read by Init but not declared, so nothing reading the schema knows it exists", tc.key)
			}
			if parameter.Type != "bool" {
				t.Fatalf("%s declared as %q", tc.key, parameter.Type)
			}
			// A declaration that lies about the default is worse than none: it
			// tells a caller the option is off when the probe has it on.
			declaredDefault, isBool := parameter.Default.(bool)
			if !isBool || declaredDefault != tc.defaultOf {
				t.Fatalf("%s declares default %#v, the probe defaults to %v", tc.key, parameter.Default, tc.defaultOf)
			}
			if parameter.Description == "" {
				t.Fatalf("%s has no description", tc.key)
			}

			// And the declaration is not decoration: Init must move the value.
			module := newSMBNativeProbeModule()
			if err := module.Init("smb-native-probe-test", map[string]any{tc.key: tc.want}); err != nil {
				t.Fatalf("init: %v", err)
			}
			if got := tc.optionOf(module.options); got != tc.want {
				t.Fatalf("%s set to %v but the probe holds %v", tc.key, tc.want, got)
			}
		})
	}
}

// The defaults are what a scan gets when nothing sets them, so they are worth
// pinning next to the declaration that advertises them.
func TestSMBNativeProbeModule_DefaultsAreBothOn(t *testing.T) {
	t.Parallel()

	module := newSMBNativeProbeModule()
	if err := module.Init("smb-native-probe-test", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if !module.options.IncludeEnum || !module.options.FallbackToNetBIOS {
		t.Fatalf("both options default on, got include_enum=%v fallback_to_netbios=%v",
			module.options.IncludeEnum, module.options.FallbackToNetBIOS)
	}
}
