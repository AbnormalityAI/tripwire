package tripwire

import (
	"regexp"
	"sort"
	"strings"
)

func (m Matcher) part(f Fixture) string {
	if m.Part == "header" {
		keys := make([]string, 0, len(f.Headers))
		for k := range f.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			b.WriteString(k + ": " + f.Headers[k] + "\n")
		}
		return b.String()
	}
	return f.Body
}

func (m Matcher) eval(f Fixture) bool {
	var res bool
	all := m.Mode == "and"
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if f.Status == s {
				res = true
			}
		}
	case "word":
		txt := m.part(f)
		res = all
		for _, w := range m.Words {
			has := strings.Contains(txt, w)
			if all {
				res = res && has
			} else {
				res = res || has
			}
		}
	case "regex":
		txt := m.part(f)
		res = all
		for _, r := range m.Regex {
			re, err := regexp.Compile(r)
			has := err == nil && re.MatchString(txt)
			if all {
				res = res && has
			} else {
				res = res || has
			}
		}
	}
	if m.Negative {
		return !res
	}
	return res
}

// Fires reports whether the template matches the fixture.
func (t Template) Fires(f Fixture) bool {
	if len(t.Matchers) == 0 {
		return false
	}
	or := t.Cond == "or"
	res := !or
	for _, m := range t.Matchers {
		v := m.eval(f)
		if or {
			res = res || v
		} else {
			res = res && v
		}
	}
	return res
}
