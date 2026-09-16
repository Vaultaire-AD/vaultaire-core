// Package ratelimit freine la force brute en ligne sur les mots de passe.
//
// # Le problème
//
// Trois portes vérifient un mot de passe : le portail web, le bind LDAP et les
// trames Ducky 02_03 / 03_01. Une seule des trois — LDAP — comptait les échecs.
// Le portail web et le canal Ducky acceptaient autant de tentatives que le
// réseau en portait.
//
// Ce paquet est la généralisation de ce que faisait `LDAP_Throttle.go`, qui n'en
// est plus qu'un mince adaptateur. La logique est écrite une fois ; les trois
// portes partagent les mêmes compteurs, ce qui compte : sans cela, un attaquant
// bloqué sur LDAP recommencerait sur le web avec un compteur neuf.
//
// # Un COÛT, jamais un verrou
//
// Le réflexe serait de désactiver le compte après N échecs. C'est précisément ce
// qu'il ne faut pas faire : un verrou permet à n'importe qui de mettre le compte
// d'un tiers hors service en échouant délibérément. On offrirait une panne à la
// demande pour se protéger d'une attaque.
//
// Ici le coût monte et rien n'est jamais définitif : trois essais sans gêne,
// puis une échéance de 1, 2, 4, 8, 16 secondes, plafonnée à 30, et l'oubli
// complet après un quart d'heure sans échec.
//
// # Un REFUS jusqu'à une échéance, pas une attente
//
// La tentative trop rapprochée est refusée immédiatement ; on ne fait pas dormir
// l'appelant. La distinction n'est pas cosmétique :
//
//   - côté Ducky, les trames d'authentification arrivent sur la session MACHINE,
//     partagée par tous les utilisateurs du poste, et `Split_Action` les traite
//     dans la boucle de lecture. Y dormir bloquerait le canal entier — GPO,
//     révocation et les autres utilisateurs compris ;
//   - côté web, dormir retient une goroutine et une connexion par tentative.
//     Le freinage se paierait en ressources du serveur, c'est-à-dire du mauvais
//     côté.
//
// # DEUX compteurs, et il en faut deux
//
// Par compte ET par source, la plus lointaine des deux échéances l'emportant.
// Chacun pris seul se contourne :
//
//   - par compte seul : essayer UN mot de passe courant sur dix mille comptes
//     n'atteint le seuil d'aucun d'eux ;
//   - par source seule : un botnet répartit et passe.
//
// # Ce que ce paquet ne fait pas
//
// Il ne couvre que l'attaque EN LIGNE. Sur une base de mots de passe volée,
// aucune limite côté serveur ne joue : seule la robustesse du hachage décide, et
// celui de Vaultaire est un SHA-256 en un tour. Voir le point 29 de
// docs/Developement/TO-DO.md.
package ratelimit

import (
	"fmt"
	"sync"
	"time"

	"vaultaire/core/logs"
)

// Barème.
//
// Des variables et non des constantes : un exploitant peut les durcir au
// démarrage, et les tests les déplacent pour ne pas attendre réellement.
var (
	// EssaisGratuits : nombre d'échecs tolérés avant que l'échéance ne s'applique.
	//
	// Trois, et pas cinq. Un humain se trompe une ou deux fois — de casse, de
	// disposition clavier. Au troisième, il relit ce qu'il tape.
	//
	// ⚠️ Les compteurs vivent EN MÉMOIRE, donc par core. Un attaquant qui
	// répartit ses essais sur N cores obtient N fois ces essais gratuits. La
	// partie exponentielle domine très vite et le nombre de cores est petit :
	// c'est le compromis assumé pour ne rien écrire en base sur un chemin
	// d'authentification.
	EssaisGratuits = 3

	// DelaiBase : première échéance, doublée à chaque échec suivant.
	DelaiBase = 1 * time.Second

	// DelaiMaximum plafonne l'échéance.
	//
	// Au-delà, allonger ne freine plus guère un script — il a déjà changé de
	// cible — mais donne prise à un déni de service : maintenir un compte hors
	// d'usage ne coûte alors qu'un échec par plafond. Le plafond borne ce que
	// vaut cette nuisance.
	DelaiMaximum = 30 * time.Second

	// Oubli : durée sans échec au terme de laquelle le compteur retombe à zéro.
	//
	// Assez long pour qu'un script lent ne se réinitialise pas gratuitement,
	// assez court pour que l'utilisateur qui revient le lendemain reparte propre.
	Oubli = 15 * time.Minute
)

// compteur porte l'état d'une clé — un compte, ou une source.
type compteur struct {
	echecs      int
	dernier     time.Time
	refuseJusqu time.Time
}

var (
	mu            sync.Mutex
	parCompte     = map[string]*compteur{}
	parSource     = map[string]*compteur{}
	dernierePurge time.Time
)

// maintenant est remplaçable par les tests : sans cela, éprouver l'oubli
// demanderait d'attendre un quart d'heure.
var maintenant = time.Now

// Autorise dit si une tentative peut être évaluée, et sinon ce qu'il reste à
// patienter.
//
// Ne modifie aucun compteur : une tentative refusée ici n'en est pas une, et la
// compter ferait grandir l'échéance à chaque coup de sonde. L'attaquant
// s'infligerait un blocage perpétuel — ce qui semble une bonne nouvelle, mais
// vaut aussi pour le client mal configuré qui réessaie en boucle, et pour le
// compte d'un tiers qu'on veut mettre hors d'usage.
//
// À appeler AVANT la recherche du compte : sinon un balayage de noms
// d'utilisateur interroge la base à chaque essai, le coût pour le serveur reste
// entier, et le temps de réponse distingue le compte existant de l'inconnu.
func Autorise(compte, source string) (bool, time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	purgerSiNecessaire()

	n := maintenant()
	var reste time.Duration
	for _, c := range []*compteur{parCompte[compte], parSource[source]} {
		if c == nil {
			continue
		}
		if r := c.refuseJusqu.Sub(n); r > reste {
			// La PLUS LOINTAINE des deux échéances, et non leur somme : les deux
			// compteurs décrivent la même tentative vue sous deux angles.
			reste = r
		}
	}
	if reste > 0 {
		return false, reste
	}
	return true, 0
}

// Echec enregistre une tentative évaluée et rejetée.
//
// À appeler pour TOUT refus d'authentification, y compris quand le compte
// n'existe pas : deviner des noms est exactement ce que fait un balayage, et ne
// pas le compter laisserait ce chemin entièrement libre.
func Echec(compte, source string) {
	mu.Lock()
	defer mu.Unlock()

	incrementer(parCompte, compte)
	incrementer(parSource, source)

	// Journalisé au franchissement du seuil, une seule fois, et non à chaque
	// échec : répéter la ligne reproduirait le bruit qu'on vient de retirer des
	// journaux et noierait le signal qu'on veut voir.
	if c := parCompte[compte]; c != nil && c.echecs == EssaisGratuits+1 {
		logs.Write_LogCode("SECURITY", logs.CodeAuthLoginDenied, fmt.Sprintf(
			"echecs repetes sur le compte %q : les tentatives sont desormais espacees", compte))
	}
	if s := parSource[source]; s != nil && s.echecs == EssaisGratuits+1 {
		logs.Write_LogCode("SECURITY", logs.CodeAuthLoginDenied, fmt.Sprintf(
			"echecs repetes depuis %q : les tentatives sont desormais espacees", source))
	}
}

func incrementer(m map[string]*compteur, cle string) {
	if cle == "" {
		return
	}
	c := m[cle]
	if c == nil {
		c = &compteur{}
		m[cle] = c
	}
	n := maintenant()
	if !c.dernier.IsZero() && n.Sub(c.dernier) > Oubli {
		c.echecs = 0
	}
	c.echecs++
	c.dernier = n

	if c.echecs > EssaisGratuits {
		d := DelaiBase << (c.echecs - EssaisGratuits - 1)
		// d <= 0 attrape le débordement : le décalage finit par sortir de
		// l'int64 et rend un négatif, qu'on lirait comme « aucune échéance ».
		if d > DelaiMaximum || d <= 0 {
			d = DelaiMaximum
		}
		c.refuseJusqu = n.Add(d)
	}
}

// Reussite efface les deux compteurs.
//
// Les DEUX, et pas seulement le compte : une authentification réussie depuis une
// source prouve qu'elle n'est pas qu'une machine à essayer. N'effacer que le
// compte laisserait un poste partagé — salle de formation, serveur de rebond —
// pénalisé par les erreurs de ses occupants précédents.
func Reussite(compte, source string) {
	mu.Lock()
	defer mu.Unlock()
	delete(parCompte, compte)
	delete(parSource, source)
}

// purgerSiNecessaire retire les compteurs oubliés.
//
// Sans purge, les deux tables grossissent indéfiniment : une entrée par nom
// d'utilisateur inventé et par adresse ayant tenté sa chance — c'est exactement
// ce qu'un balayage produit en masse, et l'attaquant obtiendrait une fuite de
// mémoire pour le prix d'une requête.
//
// Amortie plutôt que périodique, pour ne pas porter une goroutine de plus.
// L'appelant DOIT détenir mu.
func purgerSiNecessaire() {
	n := maintenant()
	if n.Sub(dernierePurge) < Oubli {
		return
	}
	dernierePurge = n
	for _, m := range []map[string]*compteur{parCompte, parSource} {
		for cle, c := range m {
			if n.Sub(c.dernier) > Oubli && n.After(c.refuseJusqu) {
				delete(m, cle)
			}
		}
	}
}

// Etat rend les compteurs d'échecs des deux clés, pour les tests et le
// diagnostic.
func Etat(compte, source string) (echecsCompte, echecsSource int) {
	mu.Lock()
	defer mu.Unlock()
	if c := parCompte[compte]; c != nil {
		echecsCompte = c.echecs
	}
	if s := parSource[source]; s != nil {
		echecsSource = s.echecs
	}
	return
}

// Reinitialiser vide tout. Réservé aux tests.
func Reinitialiser() {
	mu.Lock()
	defer mu.Unlock()
	parCompte = map[string]*compteur{}
	parSource = map[string]*compteur{}
	dernierePurge = time.Time{}
}
