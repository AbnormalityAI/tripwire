package tripwire

import (
	"sort"
)

// Score is the confusion matrix for one template across all fixtures.
type Score struct {
	ID             string
	TP, FP, FN, TN int
	FalsePositives []string // fixture names
	Missed         []string
}

// Precision is TP/(TP+FP); 1 when nothing fired.
func (s Score) Precision() float64 {
	if s.TP+s.FP == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

// Recall is TP/(TP+FN); 1 when nothing was expected.
func (s Score) Recall() float64 {
	if s.TP+s.FN == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FN)
}

// Run executes every template against every fixture.
func Run(ts []Template, fs []Fixture) []Score {
	var out []Score
	for _, t := range ts {
		s := Score{ID: t.ID}
		for _, f := range fs {
			expected := false
			for _, e := range f.Expect {
				if e == t.ID {
					expected = true
				}
			}
			fired := t.Fires(f)
			switch {
			case fired && expected:
				s.TP++
			case fired && !expected:
				s.FP++
				s.FalsePositives = append(s.FalsePositives, f.Name)
			case !fired && expected:
				s.FN++
				s.Missed = append(s.Missed, f.Name)
			default:
				s.TN++
			}
		}
		sort.Strings(s.FalsePositives)
		sort.Strings(s.Missed)
		out = append(out, s)
	}
	return out
}

// UnknownExpectations returns fixture expectations naming a template that
// does not exist, which usually means a typo in the ground truth.
func UnknownExpectations(ts []Template, fs []Fixture) []string {
	known := map[string]bool{}
	for _, t := range ts {
		known[t.ID] = true
	}
	var out []string
	for _, f := range fs {
		for _, e := range f.Expect {
			if !known[e] {
				out = append(out, f.Name+": "+e)
			}
		}
	}
	return out
}
