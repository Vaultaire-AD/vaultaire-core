package action

import (
	"testing"

	"vaultaire/core/database"
)

// Les tests de ce paquet sont de DEUX familles, et les mélanger a coûté cher.
//
//  1. Ceux qui éprouvent une règle PURE : validation d'un paramètre, forme d'un
//     message, portée déclarée, contenu du catalogue. Ils ne touchent à rien et
//     tournent partout, y compris en intégration continue.
//
//  2. Ceux qui traversent une action jusqu'à la BASE. Sans base, `database.
//     GetDatabase()` rend un pointeur nul et `database/sql` PANIQUE dessus. Une
//     panique n'échoue pas seulement le test : elle arrête tout le paquet, et
//     les résultats des autres tests disparaissent avec elle.
//
// C'est ce qui s'était produit : cinq tests paniquaient, le paquet ne rendait
// plus aucun verdict, et l'habitude s'était prise de le lancer avec un filtre
// qui les écartait. Un paquet qu'on ne lance qu'en écartant des tests ne dit
// plus rien de ce qu'il couvre.
//
// exigeBase rend cela explicite : sans base, le test est SAUTÉ, avec sa raison,
// et le reste du paquet rend son verdict. `go test ./...` redevient utilisable
// sans rien filtrer.
func exigeBase(t *testing.T) {
	t.Helper()
	if database.GetDatabase() == nil {
		t.Skip("nécessite une base de données : ce test traverse une action jusqu'au SQL " +
			"(voir docs/Developement/how it work/Tests.md)")
	}
}
