// Command tripwire lints detection templates and scores them on fixtures.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/AbnormalityAI/tripwire"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tripwire lint|score [-t templates] [-f fixtures] [-min-precision 0.9] [-min-recall 0.9]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	td := fs.String("t", "templates", "template directory")
	fd := fs.String("f", "fixtures", "fixture directory")
	minP := fs.Float64("min-precision", 0.9, "fail below this precision")
	minR := fs.Float64("min-recall", 0.9, "fail below this recall")
	fs.Parse(os.Args[2:])
	ts, err := tripwire.LoadTemplates(*td)
	die(err)
	failed := false
	switch os.Args[1] {
	case "lint":
		for _, f := range tripwire.Lint(ts) {
			fmt.Println(f)
			failed = failed || f.Error
		}
		fmt.Printf("%d templates checked\n", len(ts))
	case "score":
		fx, err := tripwire.LoadFixtures(*fd)
		die(err)
		for _, u := range tripwire.UnknownExpectations(ts, fx) {
			fmt.Println("error: fixture expects unknown template", u)
			failed = true
		}
		fmt.Printf("%-28s %3s %3s %3s %3s  %9s %6s\n", "template", "TP", "FP", "FN", "TN", "precision", "recall")
		for _, s := range tripwire.Run(ts, fx) {
			fmt.Printf("%-28s %3d %3d %3d %3d  %9.2f %6.2f\n", s.ID, s.TP, s.FP, s.FN, s.TN, s.Precision(), s.Recall())
			for _, n := range s.FalsePositives {
				fmt.Printf("    false positive on %s\n", n)
			}
			for _, n := range s.Missed {
				fmt.Printf("    missed %s\n", n)
			}
			if s.Precision() < *minP || s.Recall() < *minR {
				failed = true
			}
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
	if failed {
		os.Exit(1)
	}
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
