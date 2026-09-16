package qrcode

// Correction d'erreur Reed-Solomon sur GF(256), polynôme primitif 0x11D.
//
// Les tables d'exponentielles et de logarithmes remplacent la multiplication du
// corps par une addition d'exposants : c'est la forme habituelle, et elle évite
// d'écrire une multiplication polynomiale dans la boucle chaude.

var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	// Duplication de la table pour que exp[a+b] ne déborde jamais, a et b
	// valant chacun au plus 254.
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// generatorPoly construit le polynôme générateur de degré n.
func generatorPoly(n int) []byte {
	poly := []byte{1}
	for i := 0; i < n; i++ {
		next := make([]byte, len(poly)+1)
		for j, c := range poly {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		poly = next
	}
	return poly
}

// reedSolomon retourne les ecCount codewords de correction d'un bloc.
func reedSolomon(data []byte, ecCount int) []byte {
	gen := generatorPoly(ecCount)
	remainder := make([]byte, len(data)+ecCount)
	copy(remainder, data)

	for i := 0; i < len(data); i++ {
		factor := remainder[i]
		if factor == 0 {
			continue
		}
		for j, g := range gen {
			remainder[i+j] ^= gfMul(g, factor)
		}
	}
	return remainder[len(data):]
}
