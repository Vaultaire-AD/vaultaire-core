package command

import (
	"vaultaire/core/version"
)

// handleVersion rend la version de CE core.
//
// # Ce qu'elle ne dit pas, et pourquoi
//
// Rien sur le parc. La version des agents et des nœuds vit dans l'inventaire :
// `get -c <machine>` pour une machine, `cluster list` pour les nœuds. Les
// mélanger ici ferait une commande qui répond à deux questions selon ce qu'on
// lui passe, alors que « quelle version tourne ici » et « qui n'est pas à jour »
// se posent dans deux situations différentes.
//
// # Aucune comparaison
//
// La commande n'annonce ni « à jour » ni « obsolète ». Le core ne connaît
// aucune version de référence — il ne sait pas ce qui existe ailleurs, et
// l'inventer serait pire que se taire.
func handleVersion() string {
	return "Vaultaire core " + version.Complete() + "\n" +
		"\n" +
		"  Version des machines du parc : get -c <machine>\n" +
		"  Version des nœuds du cluster : cluster list\n"
}
