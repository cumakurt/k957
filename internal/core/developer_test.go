package core

import (
	"strings"
	"testing"
)

func TestDeveloperCredits(t *testing.T) {
	want := DeveloperDetails{"Cuma Kurt", "cumakurt@gmail.com", "https://github.com/cumakurt/k957", "https://www.linkedin.com/in/cuma-kurt-34414917/"}
	if DeveloperInfo() != want || BuildInfo().Developer != want {
		t.Fatal("developer metadata differs from the public credits")
	}
	var lines []string
	for _, row := range developerDocumentRows() {
		lines = append(lines, row.Text)
	}
	for _, value := range []string{want.Name, want.Email, want.Repository, want.LinkedIn} {
		if !strings.Contains(developerHTML, value) || !strings.Contains(strings.Join(lines, "\n"), value) {
			t.Fatalf("missing software credit: %s", value)
		}
	}
}
