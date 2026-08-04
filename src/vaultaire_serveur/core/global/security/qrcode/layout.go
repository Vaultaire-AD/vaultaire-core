package qrcode

// Placement des modules : motifs fixes, données, masquage.

// reserved marque les modules qui appartiennent aux motifs de structure et ne
// peuvent donc pas porter de données ni être masqués.
type canvas struct {
	Matrix
	reserved []bool
}

func newCanvas(version int) *canvas {
	size := 17 + 4*version
	c := &canvas{
		Matrix:   Matrix{Size: size, Modules: make([]bool, size*size)},
		reserved: make([]bool, size*size),
	}
	c.drawFunctionPatterns(version)
	return c
}

func (c *canvas) reserve(x, y int, dark bool) {
	c.set(x, y, dark)
	c.reserved[y*c.Size+x] = true
}

func (c *canvas) isReserved(x, y int) bool { return c.reserved[y*c.Size+x] }

func (c *canvas) drawFunctionPatterns(version int) {
	n := c.Size

	// Trois motifs de détection de position, dans trois coins. Le quatrième
	// coin reste libre : c'est son absence qui donne au lecteur l'orientation
	// du symbole.
	for _, p := range [][2]int{{0, 0}, {n - 7, 0}, {0, n - 7}} {
		c.drawFinder(p[0], p[1])
	}

	// Séparateurs : une ligne claire autour de chaque motif de détection.
	for _, p := range [][2]int{{0, 0}, {n - 8, 0}, {0, n - 8}} {
		for i := 0; i < 8; i++ {
			for _, q := range [][2]int{{p[0] + i, p[1] + 7}, {p[0] + 7, p[1] + i}} {
				x, y := q[0], q[1]
				if p[0] == n-8 {
					x = p[0] + i
					if q[0] == p[0]+7 {
						x = p[0]
					}
				}
				if x >= 0 && x < n && y >= 0 && y < n && !c.isReserved(x, y) {
					c.reserve(x, y, false)
				}
			}
		}
	}
	// Le calcul ci-dessus est délicat à lire ; on repasse simplement sur les
	// bandes de séparation, l'idempotence rendant l'opération sûre.
	for i := 0; i < 8; i++ {
		c.reserve(i, 7, false)
		c.reserve(7, i, false)
		c.reserve(n-1-i, 7, false)
		c.reserve(n-8, i, false)
		c.reserve(i, n-8, false)
		c.reserve(7, n-1-i, false)
	}

	// Motifs d'alignement, sauf là où ils recouvriraient un motif de détection.
	centers := alignmentCenters[version]
	for _, cy := range centers {
		for _, cx := range centers {
			if (cx == 6 && cy == 6) || (cx == 6 && cy == n-7) || (cx == n-7 && cy == 6) {
				continue
			}
			c.drawAlignment(cx, cy)
		}
	}

	// Motifs de synchronisation : une alternance qui donne l'échelle au lecteur.
	for i := 8; i < n-8; i++ {
		dark := i%2 == 0
		c.reserve(i, 6, dark)
		c.reserve(6, i, dark)
	}

	// Module sombre, toujours présent, toujours au même endroit.
	c.reserve(8, n-8, true)

	// Emplacements de l'information de format, réservés ici et remplis après le
	// choix du masque.
	for i := 0; i < 9; i++ {
		if !c.isReserved(i, 8) {
			c.reserve(i, 8, false)
		}
		if !c.isReserved(8, i) {
			c.reserve(8, i, false)
		}
	}
	for i := 0; i < 8; i++ {
		c.reserve(n-1-i, 8, false)
		c.reserve(8, n-1-i, false)
	}

	// Information de version, à partir de la version 7 seulement.
	if version >= 7 {
		bits := versionInfo(version)
		for i := 0; i < 18; i++ {
			dark := bits&(1<<uint(i)) != 0
			x, y := i/3, n-11+i%3
			c.reserve(x, y, dark)
			c.reserve(y, x, dark)
		}
	}
}

func (c *canvas) drawFinder(ox, oy int) {
	for dy := 0; dy < 7; dy++ {
		for dx := 0; dx < 7; dx++ {
			edge := dx == 0 || dx == 6 || dy == 0 || dy == 6
			core := dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4
			c.reserve(ox+dx, oy+dy, edge || core)
		}
	}
}

func (c *canvas) drawAlignment(cx, cy int) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			ring := dx == -2 || dx == 2 || dy == -2 || dy == 2
			center := dx == 0 && dy == 0
			c.reserve(cx+dx, cy+dy, ring || center)
		}
	}
}

// placeData écrit le flux de codewords en zigzag, depuis le coin bas droit.
func (c *canvas) placeData(codewords []byte) {
	n := c.Size
	bit := 0
	upward := true

	for right := n - 1; right >= 1; right -= 2 {
		// La colonne 6 porte le motif de synchronisation vertical : elle est
		// sautée, sinon tout le zigzag serait décalé d'une colonne.
		if right == 6 {
			right = 5
		}
		for i := 0; i < n; i++ {
			y := i
			if upward {
				y = n - 1 - i
			}
			for _, x := range []int{right, right - 1} {
				if c.isReserved(x, y) {
					continue
				}
				dark := false
				if bit < len(codewords)*8 {
					dark = codewords[bit/8]&(0x80>>uint(bit%8)) != 0
				}
				c.set(x, y, dark)
				bit++
			}
		}
		upward = !upward
	}
}

// maskCondition retourne true là où le masque inverse le module.
func maskCondition(pattern, x, y int) bool {
	switch pattern {
	case 0:
		return (y+x)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (y+x)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return (y*x)%2+(y*x)%3 == 0
	case 6:
		return ((y*x)%2+(y*x)%3)%2 == 0
	default:
		return ((y+x)%2+(y*x)%3)%2 == 0
	}
}

// placeAndMask essaie les huit masques et retient celui qui pénalise le moins.
//
// Le masquage n'est pas un choix esthétique : il évite les suites de modules
// identiques et les motifs ressemblant aux repères de position, qui feraient
// perdre au lecteur son point de référence.
func placeAndMask(codewords []byte, version int) *Matrix {
	var best *Matrix
	bestScore := -1

	for pattern := 0; pattern < 8; pattern++ {
		c := newCanvas(version)
		c.placeData(codewords)

		masked := Matrix{Size: c.Size, Modules: make([]bool, len(c.Modules))}
		copy(masked.Modules, c.Modules)
		for y := 0; y < c.Size; y++ {
			for x := 0; x < c.Size; x++ {
				if !c.isReserved(x, y) && maskCondition(pattern, x, y) {
					masked.Modules[y*c.Size+x] = !masked.Modules[y*c.Size+x]
				}
			}
		}
		writeFormatInfo(&masked, pattern)

		if score := penalty(&masked); bestScore < 0 || score < bestScore {
			bestScore = score
			m := masked
			best = &m
		}
	}
	return best
}

// writeFormatInfo inscrit le niveau de correction et le masque, aux deux
// emplacements prévus — la redondance permet de lire le format même si un coin
// est abîmé.
func writeFormatInfo(m *Matrix, pattern int) {
	const ecLevelM = 0b00
	data := ecLevelM<<3 | pattern

	rem := data
	for i := 0; i < 10; i++ {
		rem <<= 1
		if rem&(1<<10) != 0 {
			rem ^= 0b10100110111
		}
	}
	bits := ((data<<10 | rem) ^ 0b101010000010010)

	n := m.Size
	for i := 0; i < 15; i++ {
		dark := bits&(1<<uint(i)) != 0

		// Copie autour du motif de détection supérieur gauche.
		switch {
		case i < 6:
			m.set(8, i, dark)
		case i == 6:
			m.set(8, 7, dark)
		case i == 7:
			m.set(8, 8, dark)
		case i == 8:
			m.set(7, 8, dark)
		default:
			m.set(14-i, 8, dark)
		}

		// Seconde copie, répartie sur les deux autres coins.
		if i < 8 {
			m.set(n-1-i, 8, dark)
		} else {
			m.set(8, n-15+i, dark)
		}
	}
	m.set(8, n-8, true)
}

// versionInfo calcule les 18 bits d'information de version (BCH 18,6).
func versionInfo(version int) int {
	rem := version
	for i := 0; i < 12; i++ {
		rem <<= 1
		if rem&(1<<12) != 0 {
			rem ^= 0b1111100100101
		}
	}
	return version<<12 | rem
}
