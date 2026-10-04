package main

import (
	"os"
	"strings"
	"testing"
)

func TestWizardEnglishPrompts(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		prompts     []string
	}{
		{"collect", "1\nmissing-source\nnew.k957\nCASE\nOperator\nSynthetic scope\n", []string{"Source directory", "New output package (.k957), outside the source", "Case identifier", "Operator", "Authorized scope"}},
		{"analyze", "2\nmissing.k957\nnew-report\n", []string{"Evidence package (.k957)", "New report directory"}},
		{"invalid", "9\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := discard(t)
			t.Cleanup(withOutput(t, out, out))
			stdinFrom(t, tc.input)
			err := wizard()
			if err == nil {
				t.Fatal("expected invalid selection or unavailable evidence")
			}
			if tc.name == "invalid" && err.Error() != "invalid selection" {
				t.Fatalf("unexpected selection error: %v", err)
			}
			text, err := os.ReadFile(out.Name())
			if err != nil {
				t.Fatal(err)
			}
			for _, prompt := range append([]string{"Collection / Analysis Wizard", "1 = Collect evidence, 2 = Analyze a package"}, tc.prompts...) {
				if !strings.Contains(string(text), prompt) {
					t.Errorf("missing English prompt %q", prompt)
				}
			}
		})
	}
}
