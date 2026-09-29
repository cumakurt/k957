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
	fmt.Println("k957 · Toplama / Analiz Sihirbazı")
	mode, e := ask("1 = Delil topla, 2 = Paket analiz et")
	if e != nil {
		return e
	}
	switch mode {
	case "1":
		args := []string{"collect"}
		for _, v := range [][2]string{{"root", "Kaynak klasör"}, {"out", "Yeni çıktı paketi (.k957), kaynak dışında"}, {"case", "Vaka numarası"}, {"operator", "Operatör"}, {"scope", "Yetkilendirilmiş kapsam"}} {
			s, e := ask(v[1])
			if e != nil {
				return e
			}
			args = append(args, "--"+v[0], s)
		}
		return run(args)
	case "2":
		in, e := ask("Delil paketi (.k957)")
		if e != nil {
			return e
		}
		out, e := ask("Yeni rapor klasörü")
		if e != nil {
			return e
		}
		return run([]string{"analyze", "--in", in, "--out", out})
	}
	return fmt.Errorf("geçersiz seçim")
}
