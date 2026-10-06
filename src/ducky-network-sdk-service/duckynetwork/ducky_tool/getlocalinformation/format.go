package getlocalinformation

import (
	"fmt"
	"strings"
)

// FormatOctets écrit une quantité de mémoire comme `free -h` le fait.
//
//	8321499136  ->  7.8Gi
//	719323136   ->  686Mi
//
// # Pourquoi imiter `free -h` plutôt que choisir un format propre
//
// La colonne RAM du core reçoit les deux : les postes UNIX y écrivent la sortie
// de `free -h`, les postes Windows ce que rend cette fonction. Un format par
// système rendrait la colonne illisible — on ne compare pas « 7,7Gi » et
// « 7.75 GB » d'un coup d'œil, et c'est précisément ce qu'on fait devant un
// inventaire de parc.
//
// D'où les unités binaires suffixées « i » (Ki, Mi, Gi, Ti) et une seule
// décimale, quand elle apporte quelque chose.
//
// Le séparateur décimal est le POINT, et c'est une décision : `free` suit la
// locale, mais un service systemd tourne en locale C — le parc envoie donc des
// points. Écrire une virgule ici aurait mis les deux dans la même colonne.
func FormatOctets(octets uint64) string {
	const unite = 1024
	if octets < unite {
		return fmt.Sprintf("%dB", octets)
	}

	valeur := float64(octets)
	suffixes := []string{"Ki", "Mi", "Gi", "Ti", "Pi"}
	// i part à -1 : la PREMIÈRE division fait passer en Ki, donc à l'indice 0.
	// Incrémenter avant de diviser décalerait tout d'un cran — une mémoire de
	// 8 Gi annoncée en 8 Ti, ce qui a l'air d'une faute de frappe plutôt que
	// d'un défaut, et passe inaperçu longtemps.
	i := -1
	for valeur >= unite && i < len(suffixes)-1 {
		valeur /= unite
		i++
	}

	// Trois chiffres significatifs, comme `free -h` : « 686Mi », « 7.8Gi ».
	// Au-delà de 100, la décimale ne dit plus rien d'utile et allonge la
	// colonne.
	var texte string
	if valeur >= 100 {
		texte = fmt.Sprintf("%.0f", valeur)
	} else {
		texte = fmt.Sprintf("%.1f", valeur)
		// « 8.0Gi » se lit moins bien que « 8Gi », et `free -h` écrit le second.
		texte = strings.TrimSuffix(texte, ".0")
	}
	return texte + suffixes[i]
}
