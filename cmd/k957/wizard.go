package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func wizard() error {
	r := bufio.NewReader(os.Stdin)
	ask := func(prompt string) (string, error) {
		fmt.Print(prompt + ": ")
		s, e := r.ReadString('\n')
		return strings.TrimSpace(s), e
	}
	fmt.Println("k957 · Collection / Analysis Wizard")
	mode, e := ask("1 = Collect evidence, 2 = Analyze a package")
	if e != nil {
		return e
	}
	switch mode {
	case "1":
		args := []string{"collect"}
		for _, v := range [][2]string{{"root", "Source directory"}, {"out", "New output package (.k957), outside the source"}, {"case", "Case identifier"}, {"operator", "Operator"}, {"scope", "Authorized scope"}} {
			s, e := ask(v[1])
			if e != nil {
				return e
			}
			args = append(args, "--"+v[0], s)
		}
		return run(args)
	case "2":
		in, e := ask("Evidence package (.k957)")
		if e != nil {
			return e
		}
		out, e := ask("New report directory")
		if e != nil {
			return e
		}
		return run([]string{"analyze", "--in", in, "--out", out})
	}
	return fmt.Errorf("invalid selection")
}
