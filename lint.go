package tripwire

import (
	"fmt"
	"regexp"
	"strings"
)

// Finding is one lint problem.
type Finding struct {
	File, Rule, Message string
	Error               bool
}

func (f Finding) String() string {
	lvl := "warn"
	if f.Error {
		lvl = "error"
	}
	return fmt.Sprintf("%s: %s [%s] %s", f.File, lvl, f.Rule, f.Message)
}

var (
	idRe       = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	broad      = map[string]bool{".*": true, ".+": true, "": true, `\w+`: true, `.`: true, `[\s\S]*`: true}
)

// Lint checks templates for structural and quality problems.
func Lint(ts []Template) []Finding {
	var out []Finding
	seen := map[string]string{}
	add := func(t Template, rule string, isErr bool, f string, a ...any) {
		out = append(out, Finding{t.File, rule, fmt.Sprintf(f, a...), isErr})
	}
	for _, t := range ts {
		if !idRe.MatchString(t.ID) {
			add(t, "id-format", true, "id %q must be lowercase-kebab-case", t.ID)
		}
		if prev, dup := seen[t.ID]; dup {
			add(t, "id-duplicate", true, "id %q already used in %s", t.ID, prev)
		}
		seen[t.ID] = t.File
		if t.Info.Name == "" {
			add(t, "info-name", true, "info.name is required")
		}
		if !severities[t.Info.Severity] {
			add(t, "severity", true, "severity %q not one of info|low|medium|high|critical", t.Info.Severity)
		}
		if len(t.Info.Tags) == 0 {
			add(t, "tags", false, "no tags; templates are hard to filter without them")
		}
		if t.Cond != "" && t.Cond != "and" && t.Cond != "or" {
			add(t, "condition", true, "matchers-condition must be and|or, got %q", t.Cond)
		}
		if len(t.Matchers) == 0 {
			add(t, "matchers-empty", true, "no matchers")
		}
		allNeg := len(t.Matchers) > 0
		onlyStatus := len(t.Matchers) > 0
		for i, m := range t.Matchers {
			if !m.Negative {
				allNeg = false
			}
			if m.Type != "status" {
				onlyStatus = false
			}
			if m.Mode != "" && m.Mode != "and" && m.Mode != "or" {
				add(t, "matcher-condition", true, "matcher %d: condition must be and|or, got %q", i, m.Mode)
			}
			switch m.Type {
			case "word":
				if len(m.Words) == 0 {
					add(t, "matcher-empty", true, "matcher %d: word matcher has no words", i)
				}
				for _, w := range m.Words {
					if len(strings.TrimSpace(w)) < 4 {
						add(t, "word-short", false, "matcher %d: word %q is under 4 characters and will over-match", i, w)
					}
				}
			case "regex":
				if len(m.Regex) == 0 {
					add(t, "matcher-empty", true, "matcher %d: regex matcher has no patterns", i)
				}
				for _, r := range m.Regex {
					if _, err := regexp.Compile(r); err != nil {
						add(t, "regex-invalid", true, "matcher %d: %v", i, err)
					} else if broad[r] {
						add(t, "regex-broad", false, "matcher %d: regex %q matches nearly anything", i, r)
					}
				}
			case "status":
				if len(m.Status) == 0 {
					add(t, "matcher-empty", true, "matcher %d: no status codes", i)
				}
			default:
				add(t, "matcher-type", true, "matcher %d: unknown type %q", i, m.Type)
			}
			if m.Part != "" && m.Part != "body" && m.Part != "header" {
				add(t, "part", true, "matcher %d: part must be body|header", i)
			}
		}
		if allNeg {
			add(t, "all-negative", false, "every matcher is negative; the template fires on almost any response")
		}
		if onlyStatus && t.Cond != "or" {
			add(t, "status-only", false, "status-only template has no content check and will produce false positives")
		}
	}
	return out
}
