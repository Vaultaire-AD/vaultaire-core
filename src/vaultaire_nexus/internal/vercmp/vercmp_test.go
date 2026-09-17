package vercmp

import "testing"

func TestCompare(t *testing.T) {
	cas := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.9", "1.10", -1},
		{"2.1.0", "2.1", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0a", "1.0", 1},
		{"1.0", "1.0.a", -1},
		{"v2.1.3", "2.1.10", -1},
		{"010", "10", 0},
		{"1.0-2", "1.0-10", -1},
		{"5.0.el9", "5.0.el8", 1},
	}
	for _, c := range cas {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, attendu %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, attendu %d (antisymétrie)", c.b, c.a, got, -c.want)
		}
	}
}
