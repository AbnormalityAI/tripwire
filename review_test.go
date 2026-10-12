package tripwire

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInvalidMatcherConditionIsLintError(t *testing.T) {
	ts := []Template{{ID: "test", Info: Info{Name: "test", Severity: "low", Tags: []string{"test"}},
		Matchers: []Matcher{{Type: "word", Words: []string{"alpha", "beta"}, Mode: "nand"}}}}
	for _, f := range Lint(ts) {
		if f.Error && f.Rule == "matcher-condition" {
			return
		}
	}
	t.Fatal("invalid matcher condition accepted")
}

func TestMissingOrEmptyDirectoriesRejected(t *testing.T) {
	if _, err := LoadTemplates(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing template directory accepted")
	}
	if _, err := LoadTemplates(t.TempDir()); err == nil {
		t.Error("empty template directory accepted")
	}
	if _, err := LoadFixtures(t.TempDir()); err == nil {
		t.Error("empty fixture directory accepted")
	}
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o600)
	if _, err := LoadFixtures(f); err == nil {
		t.Error("file passed as directory accepted")
	}
}

func TestExtraYAMLDocumentsRejected(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "x.yaml"), []byte("id: x\n---\nunknown: true\n"), 0o600)
	if _, err := LoadTemplates(d); err == nil {
		t.Fatal("trailing YAML document ignored")
	}
	d = t.TempDir()
	os.WriteFile(filepath.Join(d, "x.yaml"), []byte(""), 0o600)
	if _, err := LoadTemplates(d); err == nil {
		t.Fatal("empty YAML file accepted")
	}
}

func TestHeaderRenderingIsDeterministic(t *testing.T) {
	f := Fixture{Headers: map[string]string{"B": "2", "A": "1", "C": "3"}}
	m := Matcher{Type: "word", Part: "header", Words: []string{"A: 1\nB: 2\nC: 3\n"}}
	for i := 0; i < 50; i++ {
		if !m.eval(f) {
			t.Fatal("header order varies between runs")
		}
	}
}
