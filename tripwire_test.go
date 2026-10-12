package tripwire

import "testing"

func load(t *testing.T) ([]Template, []Fixture) {
	ts, err := LoadTemplates("templates")
	if err != nil {
		t.Fatal(err)
	}
	fx, err := LoadFixtures("fixtures")
	if err != nil {
		t.Fatal(err)
	}
	return ts, fx
}

func TestShippedTemplatesLintClean(t *testing.T) {
	ts, _ := load(t)
	for _, f := range Lint(ts) {
		if f.Error {
			t.Errorf("%s", f)
		}
	}
}

func TestLintCatchesProblems(t *testing.T) {
	bad := []Template{
		{ID: "Bad_ID", File: "a", Info: Info{Severity: "urgent"}, Matchers: []Matcher{{Type: "regex", Regex: []string{"(unclosed"}}}},
		{ID: "dup", File: "b", Info: Info{Name: "x", Severity: "low", Tags: []string{"t"}}, Matchers: []Matcher{{Type: "word", Words: []string{"ab"}}}},
		{ID: "dup", File: "c", Info: Info{Name: "x", Severity: "low"}},
		{ID: "broad", File: "d", Info: Info{Name: "x", Severity: "low"}, Matchers: []Matcher{{Type: "regex", Regex: []string{".*"}}}},
	}
	got := map[string]bool{}
	for _, f := range Lint(bad) {
		got[f.Rule] = true
	}
	for _, r := range []string{"id-format", "severity", "info-name", "regex-invalid", "id-duplicate", "word-short", "matchers-empty", "regex-broad", "tags"} {
		if !got[r] {
			t.Errorf("rule %s did not fire", r)
		}
	}
}

func TestScoresOnFixtures(t *testing.T) {
	ts, fx := load(t)
	if u := UnknownExpectations(ts, fx); len(u) > 0 {
		t.Fatalf("unknown expectations: %v", u)
	}
	by := map[string]Score{}
	for _, s := range Run(ts, fx) {
		by[s.ID] = s
	}
	for _, id := range []string{"exposed-env-file", "git-config-exposure", "directory-listing", "debug-stacktrace", "missing-hsts"} {
		s := by[id]
		if s.FP != 0 || s.FN != 0 {
			t.Errorf("%s should be perfect: %+v", id, s)
		}
	}
	// The sloppy template must be flagged by the harness: it over-matches.
	s := by["sloppy-admin-panel"]
	if s.FP != 1 || s.Precision() >= 0.9 {
		t.Errorf("expected the sloppy template to produce one false positive, got %+v", s)
	}
}

func TestNegativeAndOrSemantics(t *testing.T) {
	f := Fixture{Status: 200, Body: "hello world"}
	or := Template{Cond: "or", Matchers: []Matcher{{Type: "word", Words: []string{"nope"}}, {Type: "status", Status: []int{200}}}}
	and := Template{Matchers: or.Matchers}
	if !or.Fires(f) || and.Fires(f) {
		t.Fatal("and/or semantics wrong")
	}
	neg := Template{Matchers: []Matcher{{Type: "word", Words: []string{"nope"}, Negative: true}}}
	if !neg.Fires(f) {
		t.Fatal("negative matcher should fire")
	}
}
