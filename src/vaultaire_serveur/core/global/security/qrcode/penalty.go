package qrcode

// Notation des masques, selon les quatre règles de la norme.
//
// Le score le plus BAS gagne. Chaque règle sanctionne une forme qui gêne la
// lecture : les longues plages uniformes, les blocs pleins, les motifs
// ressemblant à un repère de position, et un déséquilibre global entre sombre
// et clair.

func penalty(m *Matrix) int {
	return penaltyRuns(m) + penaltyBlocks(m) + penaltyFinderLike(m) + penaltyBalance(m)
}

// penaltyRuns : cinq modules identiques alignés coûtent 3, puis 1 par module
// supplémentaire.
func penaltyRuns(m *Matrix) int {
	score := 0
	count := func(get func(i, j int) bool) {
		for i := 0; i < m.Size; i++ {
			run, prev := 1, get(i, 0)
			for j := 1; j < m.Size; j++ {
				cur := get(i, j)
				if cur == prev {
					run++
					continue
				}
				if run >= 5 {
					score += 3 + (run - 5)
				}
				run, prev = 1, cur
			}
			if run >= 5 {
				score += 3 + (run - 5)
			}
		}
	}
	count(func(y, x int) bool { return m.at(x, y) })
	count(func(x, y int) bool { return m.at(x, y) })
	return score
}

// penaltyBlocks : chaque carré plein de 2x2 coûte 3.
func penaltyBlocks(m *Matrix) int {
	score := 0
	for y := 0; y < m.Size-1; y++ {
		for x := 0; x < m.Size-1; x++ {
			v := m.at(x, y)
			if v == m.at(x+1, y) && v == m.at(x, y+1) && v == m.at(x+1, y+1) {
				score += 3
			}
		}
	}
	return score
}

// penaltyFinderLike : la séquence 1:1:3:1:1 bordée de quatre modules clairs
// imite un repère de position et coûte 40.
func penaltyFinderLike(m *Matrix) int {
	patterns := [][]bool{
		{true, false, true, true, true, false, true, false, false, false, false},
		{false, false, false, false, true, false, true, true, true, false, true},
	}
	score := 0
	match := func(get func(i int) bool, n int) {
		for start := 0; start+11 <= n; start++ {
			for _, p := range patterns {
				ok := true
				for k := 0; k < 11; k++ {
					if get(start+k) != p[k] {
						ok = false
						break
					}
				}
				if ok {
					score += 40
				}
			}
		}
	}
	for i := 0; i < m.Size; i++ {
		row, col := i, i
		match(func(j int) bool { return m.at(j, row) }, m.Size)
		match(func(j int) bool { return m.at(col, j) }, m.Size)
	}
	return score
}

// penaltyBalance sanctionne l'écart à 50 % de modules sombres, par tranches de
// 5 points de pourcentage.
func penaltyBalance(m *Matrix) int {
	dark := 0
	for _, v := range m.Modules {
		if v {
			dark++
		}
	}
	total := len(m.Modules)
	percent := dark * 100 / total
	deviation := percent - 50
	if deviation < 0 {
		deviation = -deviation
	}
	return (deviation / 5) * 10
}
