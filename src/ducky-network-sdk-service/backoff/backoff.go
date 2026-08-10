package backoff

import (
	"crypto/rand"
	"math/big"
	"time"
)

// Dégressivité des tentatives de reconnexion.
//
// # Le défaut que cela corrige
//
// L'agent comme le SDK réessayaient toutes les 30 secondes, indéfiniment, sans
// variation. Le paquet vivait dans l'agent seul ; il est ici pour que tout
// programme du socle en profite — proxy compris, qui avait exactement le même
// défaut.
//
// Deux conséquences. Un core qui redémarre voit revenir TOUT le parc en même
// temps, toutes les 30 secondes, chacune de ces connexions réclamant une
// poignée de main RSA-4096. La charge de reprise devient alors le problème
// suivant, et elle se répète tant que le core n'a pas tenu.
//
// Et un core durablement absent — maintenance, panne réseau — reçoit la même
// sollicitation pendant des heures, pour rien.
//
// # Ce que fait la version ci-dessous
//
// Le délai double à chaque échec, jusqu'à un plafond. Une coupure brève est
// donc rattrapée vite ; une absence longue cesse de coûter.
//
// S'y ajoute une DISPERSION aléatoire, et c'est elle qui compte le plus pour un
// parc : sans elle, mille agents qui perdent le core au même instant le
// retrouvent au même instant, et la dégressivité les garde synchronisés au lieu
// de les étaler.
const (
	// Court au départ : une coupure d'une seconde ne doit pas coûter trente
	// secondes d'indisponibilité.
	DelaiInitial = 2 * time.Second

	// Plafond. Au-delà, allonger n'apporte plus rien et retarde seulement la
	// reprise quand le core revient.
	DelaiMaximum = 5 * time.Minute

	// Dispersion : jusqu'à 30 % du délai, en plus ou en moins.
	DispersionMax = 30
)

// Backoff porte l'état d'une suite de tentatives.
//
// Pas de verrou : une suite appartient à une boucle de reconnexion, donc à une
// seule goroutine. Deux boucles concurrentes veulent deux suites distinctes —
// les partager les ferait se rallonger mutuellement.
type Backoff struct {
	delai time.Duration
}

// New démarre une nouvelle suite.
func New() *Backoff { return &Backoff{delai: DelaiInitial} }

// Reset remet la suite à zéro.
//
// À appeler dès qu'une connexion ABOUTIT, sinon une reconnexion réussie après
// une longue absence garderait le délai maximal pour la panne suivante — et
// une coupure d'une seconde coûterait cinq minutes.
func (b *Backoff) Reset() { b.delai = DelaiInitial }

// Prochain rend le délai à attendre, puis double pour la fois suivante.
func (b *Backoff) Prochain() time.Duration {
	if b.delai <= 0 {
		b.delai = DelaiInitial
	}
	attente := avecDispersion(b.delai)

	b.delai *= 2
	if b.delai > DelaiMaximum {
		b.delai = DelaiMaximum
	}
	return attente
}

// avecDispersion écarte le délai de ±DispersionMax pour cent.
//
// crypto/rand et non math/rand : math/rand non initialisé produit la MÊME suite
// sur chaque machine, ce qui synchroniserait exactement ce que la dispersion
// cherche à étaler.
func avecDispersion(d time.Duration) time.Duration {
	if d <= 0 {
		return DelaiInitial
	}
	amplitude := int64(d) * DispersionMax / 100
	if amplitude <= 0 {
		return d
	}

	n, err := rand.Int(rand.Reader, big.NewInt(2*amplitude))
	if err != nil {
		// Sans aléa, on garde le délai nominal : mieux vaut un parc synchronisé
		// qu'un agent qui ne se reconnecte pas.
		return d
	}
	return d + time.Duration(n.Int64()-amplitude)
}
