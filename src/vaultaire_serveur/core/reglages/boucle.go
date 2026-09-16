package reglages

import (
	"time"

	"vaultaire/core/logs"
)

// Boucle exécute `travail` périodiquement, à la cadence du réglage `cle`.
//
// # Pourquoi ce n'est pas un time.Ticker
//
// Un `time.NewTicker(reglages.Duree(cle))` lit la période UNE FOIS, à la
// création. Changer le réglage n'aurait alors aucun effet avant un redémarrage
// du core — c'est-à-dire une coupure du parc pour ajuster une cadence.
//
// Pire : rien ne le dirait. L'exploitant verrait sa nouvelle valeur en base et
// dans l'interface, et le comportement resterait l'ancien. Un réglage qui
// s'affiche sans agir est plus trompeur que pas de réglage du tout.
//
// Ici la période est relue à CHAQUE tour. Elle passe par le cache du paquet, qui
// la garde trente secondes : le changement prend donc effet au tour suivant, sans
// interroger la base à chaque fois.
//
// # Le premier tour attend
//
// `travail` n'est pas exécuté immédiatement. Toutes les boucles concernées sont
// des balayages : les lancer au démarrage ferait travailler le core au moment
// précis où il a le plus à faire — ouverture des écoutes, reconnexion de tout le
// parc — et sur des tables encore vides.
//
// Ne rend jamais la main : à lancer dans une goroutine.
func Boucle(cle string, travail func()) {
	nom := cle
	if d, ok := index[cle]; ok {
		nom = d.Libelle
	}

	for {
		d := Duree(cle)
		if d <= 0 {
			// Une période nulle ferait tourner la boucle sans repos et
			// consommerait un cœur entier. Cela ne peut venir que d'une clé
			// inconnue — les bornes du catalogue interdisent zéro — donc d'une
			// faute de programmation : on le dit et on s'arrête, plutôt que de
			// tourner à vide en silence.
			logs.Write_Log("ERROR",
				"boucle « "+nom+" » : période nulle pour le réglage "+cle+
					", boucle arrêtée. C'est une clé inconnue du catalogue.")
			return
		}

		time.Sleep(d)
		travail()
	}
}
