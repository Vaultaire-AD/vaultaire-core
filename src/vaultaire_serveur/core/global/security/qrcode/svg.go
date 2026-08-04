package qrcode

import (
	"fmt"
	"html"
	"strings"
)

// SVG rend la matrice en SVG, prêt à être inséré dans une page.
//
// La marge de quatre modules n'est pas décorative : la norme l'exige, et sans
// elle beaucoup de lecteurs échouent à isoler le symbole de ce qui l'entoure.
//
// Les modules sombres sont fusionnés en segments horizontaux plutôt que dessinés
// un par un : un QR de version 6 fait 41x41, soit près de 1 700 rectangles là où
// quelques centaines suffisent.
func SVG(m *Matrix, pixelsPerModule int, description string) string {
	if pixelsPerModule < 1 {
		pixelsPerModule = 4
	}
	const quiet = 4
	total := (m.Size + 2*quiet) * pixelsPerModule

	var b strings.Builder
	fmt.Fprintf(&b,
		`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s">`,
		total, total, m.Size+2*quiet, m.Size+2*quiet, html.EscapeString(description))
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" fill="#ffffff"/>`)
	b.WriteString(`<path fill="#000000" d="`)

	for y := 0; y < m.Size; y++ {
		x := 0
		for x < m.Size {
			if !m.at(x, y) {
				x++
				continue
			}
			run := 1
			for x+run < m.Size && m.at(x+run, y) {
				run++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x+quiet, y+quiet, run, run)
			x += run
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

// EncodeSVG encode content et retourne directement le SVG.
func EncodeSVG(content string, pixelsPerModule int, description string) (string, error) {
	m, err := Encode(content)
	if err != nil {
		return "", err
	}
	return SVG(m, pixelsPerModule, description), nil
}
