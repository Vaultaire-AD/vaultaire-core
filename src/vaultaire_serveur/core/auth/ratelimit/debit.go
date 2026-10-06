package ratelimit

import (
	"fmt"
	"math"
	"sync"
	"time"

	"vaultaire/core/logs"
)

// Débit par source, AVANT toute authentification (TO-DO 102).
//
// # Pourquoi un second mécanisme
//
// Autorise / Echec / Reussite raisonnent sur des ÉCHECS : ils ne freinent
// qu'après qu'une tentative a été évaluée — base lue, signature vérifiée. Sur
// l'API de commande, c'est précisément cette évaluation qui coûte : deux
// lectures en base et une vérification de signature par clé du compte visé.
// Un flot de requêtes absurdes la fait payer au core à chaque fois, et les
// échecs ne le freinent qu'au quatrième.
//
// Il faut donc borner le VOLUME, par source, avant même de lire le corps — sans
// savoir de quel compte il s'agit.
//
// # Un seau à jetons, pas une fenêtre fixe
//
// Un intégrateur légitime pilote le parc EN RAFALE : un script qui crée cent
// comptes les envoie d'un coup, puis se tait une heure. Une fenêtre fixe
// (« N requêtes par minute ») le couperait au milieu de sa rafale, ou devrait
// être assez large pour ne plus rien freiner.
//
// Le seau, lui, distingue les deux : il contient `Rafale` jetons, se remplit de
// `ParSeconde` jetons par seconde, et chaque requête en prend un. Une rafale
// passe d'un coup tant que le seau est plein ; un flot SOUTENU est ramené au
// débit de remplissage, quelle que soit sa durée.
//
// # Un refus immédiat, comme le reste du paquet
//
// La requête au-delà du débit reçoit tout de suite le délai à patienter ; on ne
// la fait pas attendre. Dormir retiendrait une goroutine et une connexion par
// requête refusée : le freinage se paierait côté serveur.

// Debit borne le nombre de requêtes par source.
type Debit struct {
	nom string

	mu            sync.Mutex
	rafale        float64
	parSeconde    float64
	seaux         map[string]*seau
	dernierePurge time.Time
}

type seau struct {
	jetons float64
	vu     time.Time
	// freine dit si la source est déjà signalée au journal : une ligne au
	// passage en refus, pas une par requête refusée.
	freine bool
}

// NouveauDebit crée un débit. `nom` désigne la porte dans le journal.
func NouveauDebit(nom string, rafale int, parSeconde float64) *Debit {
	d := &Debit{nom: nom, seaux: map[string]*seau{}}
	d.Regler(rafale, parSeconde)
	return d
}

// Regler change le barème. Les seaux en cours le suivent dès la requête
// suivante : relire la configuration ne doit pas exiger de redémarrer.
func (d *Debit) Regler(rafale int, parSeconde float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if rafale < 1 {
		rafale = 1
	}
	if parSeconde <= 0 {
		parSeconde = 1
	}
	d.rafale = float64(rafale)
	d.parSeconde = parSeconde
}

// Prendre consomme un jeton pour la source, et dit sinon combien patienter.
//
// Une source vide n'est pas freinée : elle n'a rien pour la distinguer, et
// lui donner un seau commun freinerait d'un coup tous ceux qu'on n'identifie
// pas.
func (d *Debit) Prendre(source string) (bool, time.Duration) {
	if source == "" {
		return true, 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	n := maintenant()
	d.purgerSiNecessaire(n)

	s := d.seaux[source]
	if s == nil {
		s = &seau{jetons: d.rafale, vu: n}
		d.seaux[source] = s
	}
	if ecoule := n.Sub(s.vu).Seconds(); ecoule > 0 {
		s.jetons = math.Min(d.rafale, s.jetons+ecoule*d.parSeconde)
	}
	s.vu = n

	if s.jetons >= 1 {
		s.jetons--
		s.freine = false
		return true, 0
	}

	if !s.freine {
		s.freine = true
		logs.Write_LogCode("SECURITY", logs.CodeAuthLoginDenied, fmt.Sprintf(
			"%s : debit depasse depuis %q (%g requetes d'affilee, puis %g par seconde) : "+
				"les requetes suivantes sont refusees jusqu'a ce qu'il redescende",
			d.nom, source, d.rafale, d.parSeconde))
	}
	manque := (1 - s.jetons) / d.parSeconde
	return false, time.Duration(manque * float64(time.Second))
}

// purgerSiNecessaire retire les seaux redevenus pleins : ils ne portent plus
// rien qu'un seau neuf ne porterait. Sans purge, chaque adresse ayant écrit une
// fois resterait en mémoire — et un balayage d'adresses en produit beaucoup.
// L'appelant DOIT détenir d.mu.
func (d *Debit) purgerSiNecessaire(n time.Time) {
	if n.Sub(d.dernierePurge) < time.Minute {
		return
	}
	d.dernierePurge = n
	plein := time.Duration(d.rafale / d.parSeconde * float64(time.Second))
	for cle, s := range d.seaux {
		if n.Sub(s.vu) > plein {
			delete(d.seaux, cle)
		}
	}
}

// Taille rend le nombre de sources suivies, pour les tests.
func (d *Debit) Taille() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seaux)
}

// Vider oublie toutes les sources. Réservé aux tests.
func (d *Debit) Vider() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seaux = map[string]*seau{}
	d.dernierePurge = time.Time{}
}
