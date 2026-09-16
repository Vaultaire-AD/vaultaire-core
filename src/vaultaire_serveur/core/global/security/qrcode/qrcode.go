// Package qrcode encode une chaîne courte en QR code et la rend en SVG.
//
// POURQUOI UNE IMPLÉMENTATION MAISON. Ce code n'existe que pour afficher l'URI
// d'enrôlement du second facteur, qui contient le secret TOTP d'un compte. Le
// faire dessiner par une bibliothèque JavaScript servie depuis un CDN
// reviendrait à confier ce secret à un tiers ; le faire dessiner par une
// dépendance Go ajouterait du code non audité sur le chemin d'un secret
// d'authentification. Ni l'un ni l'autre pour trois cents lignes.
//
// PÉRIMÈTRE VOLONTAIREMENT ÉTROIT. Mode octet uniquement, correction d'erreur
// de niveau M, versions 1 à 10 — soit jusqu'à 213 caractères. Une URI otpauth
// en fait une centaine. Tout ce qui dépasse est refusé plutôt que tronqué : un
// QR code tronqué se lit très bien et donne un mauvais secret, ce qui est le
// pire des deux mondes.
package qrcode

import "fmt"

// blockLayout décrit le découpage en blocs d'une version, au niveau M.
//
// Les codewords de correction sont calculés PAR BLOC et non sur l'ensemble :
// c'est ce découpage qui permet à un QR code de survivre à une salissure
// localisée, puisqu'une tache ne détruit qu'une partie de chaque bloc une fois
// les blocs entrelacés.
type blockLayout struct {
	ecPerBlock int
	g1Blocks   int
	g1Data     int
	g2Blocks   int
	g2Data     int
}

// layouts[v] décrit la version v (niveau M). L'indice 0 est inutilisé.
var layouts = [11]blockLayout{
	{},
	{10, 1, 16, 0, 0},
	{16, 1, 28, 0, 0},
	{26, 1, 44, 0, 0},
	{18, 2, 32, 0, 0},
	{24, 2, 43, 0, 0},
	{16, 4, 27, 0, 0},
	{18, 4, 31, 0, 0},
	{22, 2, 38, 2, 39},
	{22, 3, 36, 2, 37},
	{26, 4, 43, 1, 44},
}

// alignmentCenters[v] donne les coordonnées des motifs d'alignement.
var alignmentCenters = [11][]int{
	nil, nil,
	{6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34},
	{6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50},
}

func (b blockLayout) dataCodewords() int {
	return b.g1Blocks*b.g1Data + b.g2Blocks*b.g2Data
}

// charCountBits vaut 8 jusqu'à la version 9, 16 au-delà, en mode octet.
func charCountBits(version int) int {
	if version <= 9 {
		return 8
	}
	return 16
}

// Matrix est une grille de modules. true = sombre.
type Matrix struct {
	Size    int
	Modules []bool
}

func (m *Matrix) at(x, y int) bool     { return m.Modules[y*m.Size+x] }
func (m *Matrix) set(x, y int, v bool) { m.Modules[y*m.Size+x] = v }

// Encode produit la matrice de modules correspondant à content.
func Encode(content string) (*Matrix, error) {
	data := []byte(content)

	version := 0
	for v := 1; v <= 10; v++ {
		capacity := layouts[v].dataCodewords()*8 - 4 - charCountBits(v)
		if len(data)*8 <= capacity {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, fmt.Errorf("contenu trop long pour un QR code de version 10 : %d octets", len(data))
	}

	codewords := buildCodewords(data, version)
	best := placeAndMask(codewords, version)
	return best, nil
}

// buildCodewords assemble le flux final : en-tête, données, remplissage,
// correction d'erreur, puis entrelacement.
func buildCodewords(data []byte, version int) []byte {
	lay := layouts[version]

	var bits bitBuffer
	bits.append(0b0100, 4) // mode octet
	bits.append(uint32(len(data)), charCountBits(version))
	for _, b := range data {
		bits.append(uint32(b), 8)
	}

	// Terminateur : au plus quatre zéros, moins s'il ne reste pas la place.
	capacity := lay.dataCodewords() * 8
	if remaining := capacity - bits.length; remaining < 4 {
		bits.append(0, remaining)
	} else {
		bits.append(0, 4)
	}
	for bits.length%8 != 0 {
		bits.append(0, 1)
	}
	// Octets de remplissage alternés, imposés par la norme.
	for pad := 0; bits.length < capacity; pad++ {
		if pad%2 == 0 {
			bits.append(0xEC, 8)
		} else {
			bits.append(0x11, 8)
		}
	}

	// Découpage en blocs, puis correction d'erreur bloc par bloc.
	var dataBlocks, ecBlocks [][]byte
	offset := 0
	for i := 0; i < lay.g1Blocks; i++ {
		block := bits.bytes[offset : offset+lay.g1Data]
		offset += lay.g1Data
		dataBlocks = append(dataBlocks, block)
		ecBlocks = append(ecBlocks, reedSolomon(block, lay.ecPerBlock))
	}
	for i := 0; i < lay.g2Blocks; i++ {
		block := bits.bytes[offset : offset+lay.g2Data]
		offset += lay.g2Data
		dataBlocks = append(dataBlocks, block)
		ecBlocks = append(ecBlocks, reedSolomon(block, lay.ecPerBlock))
	}

	// Entrelacement : on prend le premier codeword de chaque bloc, puis le
	// deuxième, etc. C'est ce qui répartit une salissure sur tous les blocs au
	// lieu d'en détruire un seul entièrement.
	var out []byte
	maxData := lay.g1Data
	if lay.g2Data > maxData {
		maxData = lay.g2Data
	}
	for i := 0; i < maxData; i++ {
		for _, b := range dataBlocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := 0; i < lay.ecPerBlock; i++ {
		for _, b := range ecBlocks {
			out = append(out, b[i])
		}
	}
	return out
}

// bitBuffer accumule des bits de poids fort vers poids faible.
type bitBuffer struct {
	bytes  []byte
	length int
}

func (b *bitBuffer) append(value uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		if b.length%8 == 0 {
			b.bytes = append(b.bytes, 0)
		}
		if value&(1<<uint(i)) != 0 {
			b.bytes[b.length/8] |= 0x80 >> uint(b.length%8)
		}
		b.length++
	}
}
