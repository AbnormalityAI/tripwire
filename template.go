// Package tripwire lints YAML detection templates and scores them against
// intentionally vulnerable local fixtures (recorded responses, no network).
package tripwire

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Matcher is one check against a fixture response.
type Matcher struct {
	Type     string   `yaml:"type"` // word | regex | status | header
	Part     string   `yaml:"part"` // body (default) | header
	Words    []string `yaml:"words"`
	Regex    []string `yaml:"regex"`
	Status   []int    `yaml:"status"`
	Negative bool     `yaml:"negative"`  // invert the result
	Mode     string   `yaml:"condition"` // and | or (within this matcher)
}

// Template is a detection rule.
type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Matchers []Matcher `yaml:"matchers"`
	Cond     string    `yaml:"matchers-condition"` // and (default) | or
	File     string    `yaml:"-"`
}

// Info is human-facing metadata.
type Info struct {
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

// Fixture is a recorded response plus ground truth.
type Fixture struct {
	Name    string            `yaml:"name"`
	Status  int               `yaml:"status"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
	// Expect lists template IDs that SHOULD fire on this fixture.
	Expect []string `yaml:"expect"`
	File   string   `yaml:"-"`
}

func loadYAML[T any](dir, kind string, set func(*T, string)) ([]T, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("%s directory: %w", kind, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s: %s is not a directory", kind, dir)
	}
	var out []T
	paths, err := filepath.Glob(filepath.Join(dir, "*.y*ml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var v T
		dec := yaml.NewDecoder(bytesReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&v); err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("%s: empty file", p)
			}
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		// One document per file: a second document would be silently
		// ignored otherwise, bypassing strict decoding.
		var extra yaml.Node
		if err := dec.Decode(&extra); err != io.EOF {
			if err == nil {
				return nil, fmt.Errorf("%s: multiple YAML documents are not allowed", p)
			}
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		set(&v, p)
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %s found in %s", kind, dir)
	}
	return out, nil
}

// LoadTemplates reads every YAML file in dir (unknown keys are errors).
func LoadTemplates(dir string) ([]Template, error) {
	return loadYAML(dir, "templates", func(t *Template, p string) { t.File = p })
}

// LoadFixtures reads every YAML fixture in dir.
func LoadFixtures(dir string) ([]Fixture, error) {
	return loadYAML(dir, "fixtures", func(f *Fixture, p string) { f.File = p })
}
