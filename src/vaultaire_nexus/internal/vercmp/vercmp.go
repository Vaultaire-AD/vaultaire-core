// Package vercmp compare des numéros de version de paquets.
//
// Algorithme de rpmvercmp, qui est aussi, à la gestion du tilde près, celui de
// dpkg : la chaîne est découpée en segments numériques et alphabétiques,
// comparés deux à deux. Un segment numérique l'emporte sur un alphabétique, et
// « ~ » trie AVANT tout, y compris la fin de chaîne (1.0~rc1 < 1.0).
//
// Il sert à désigner « la dernière version » d'un paquet et à appliquer la
// rétention. Un ordre lexicographique mettrait 1.10 avant 1.9.
package vercmp

import (
	"strings"
	"unicode"
)

// Compare rend -1, 0 ou 1.
func Compare(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	if a == b {
		return 0
	}
	for {
		a = strings.TrimLeftFunc(a, isSep)
		b = strings.TrimLeftFunc(b, isSep)

		// Tilde : trie avant tout.
		ta, tb := strings.HasPrefix(a, "~"), strings.HasPrefix(b, "~")
		if ta || tb {
			if !ta {
				return 1
			}
			if !tb {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}

		numeric := unicode.IsDigit(rune(a[0]))
		sa, ra := segment(a, numeric)
		var sb, rb string
		if numeric {
			if !unicode.IsDigit(rune(b[0])) {
				return 1 // numérique > alphabétique
			}
		} else if unicode.IsDigit(rune(b[0])) {
			return -1
		}
		sb, rb = segment(b, numeric)

		if numeric {
			sa = strings.TrimLeft(sa, "0")
			sb = strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				if len(sa) > len(sb) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
		a, b = ra, rb
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	default:
		return 1
	}
}

// Less : a < b.
func Less(a, b string) bool { return Compare(a, b) < 0 }

func isSep(r rune) bool {
	return r != '~' && !unicode.IsLetter(r) && !unicode.IsDigit(r)
}

func segment(s string, numeric bool) (seg, rest string) {
	i := 0
	for i < len(s) {
		r := rune(s[i])
		if numeric && !unicode.IsDigit(r) {
			break
		}
		if !numeric && !unicode.IsLetter(r) {
			break
		}
		i++
	}
	return s[:i], s[i:]
}
