package ldapbindunbind

import (
	"sync"
	"time"
)

// Limitation des tentatives de bind.
//
// # Pourquoi ici et pas ailleurs
//
// Le port LDAP est la surface de force brute la plus commode du produit : pas de
// captcha, pas de second facteur, un protocole binaire fait pour
// l'automatisation. Rien ne comptait les échecs.
//
// # Le double comptage
//
// Par ADRESSE SOURCE : arrête un balayage de comptes depuis une machine.
// Par COMPTE : arrête un balayage de mots de passe depuis un botnet, où chaque
// adresse ne fait qu'un ou deux essais.
//
// Aucun des deux ne suffit seul.
//
// # Un délai, pas un verrouillage
//
// Verrouiller un compte après N échecs offre un déni de service : il suffit de
// se tromper volontairement pour bloquer quelqu'un. Le délai croissant coûte
// cher à l'attaquant — quelques minutes après une dizaine d'essais — et presque
// rien à l'utilisateur qui s'est trompé une fois.
var (
	// SeuilÉchecs est le nombre d'échecs tolérés avant que le délai ne s'applique.
	SeuilÉchecs = 5

	// DélaiDeBase est le temps d'attente au premier dépassement. Il double à
	// chaque échec supplémentaire, plafonné par DélaiMaximum.
	DélaiDeBase = 2 * time.Second

	// DélaiMaximum plafonne l'attente.
	DélaiMaximum = 5 * time.Minute

	// FenêtreOubli efface le compteur après une période sans échec. Sans elle,
	// un compte accumulerait ses erreurs sur des mois.
	FenêtreOubli = 15 * time.Minute
)

type compteur struct {
	échecs     int
	dernier    time.Time
	bloquéJusq time.Time
}

var (
	throttleMu   sync.Mutex
	parSource    = map[string]*compteur{}
	parCompte    = map[string]*compteur{}
	dernierPurge time.Time
)

// BindAutorisé dit si une tentative peut être évaluée, et sinon combien de temps
// il reste à attendre.
func BindAutorisé(source, compte string) (bool, time.Duration) {
	throttleMu.Lock()
	defer throttleMu.Unlock()
	purgerSiNécessaire()

	maintenant := time.Now()
	for _, c := range []*compteur{parSource[source], parCompte[compte]} {
		if c == nil {
			continue
		}
		if maintenant.Before(c.bloquéJusq) {
			return false, c.bloquéJusq.Sub(maintenant)
		}
	}
	return true, 0
}

// EnregistrerÉchec incrémente les deux compteurs.
func EnregistrerÉchec(source, compte string) {
	throttleMu.Lock()
	defer throttleMu.Unlock()

	incrémenter(parSource, source)
	if compte != "" {
		incrémenter(parCompte, compte)
	}
}

// EnregistrerSuccès remet les compteurs à zéro.
//
// Le succès efface aussi le compteur de l'ADRESSE : sans cela, un poste partagé
// où quelqu'un s'est trompé pénaliserait les collègues qui réussissent.
func EnregistrerSuccès(source, compte string) {
	throttleMu.Lock()
	defer throttleMu.Unlock()

	delete(parSource, source)
	delete(parCompte, compte)
}

func incrémenter(m map[string]*compteur, clé string) {
	c := m[clé]
	if c == nil {
		c = &compteur{}
		m[clé] = c
	}
	maintenant := time.Now()
	if !c.dernier.IsZero() && maintenant.Sub(c.dernier) > FenêtreOubli {
		c.échecs = 0
	}
	c.échecs++
	c.dernier = maintenant

	if c.échecs > SeuilÉchecs {
		délai := DélaiDeBase << (c.échecs - SeuilÉchecs - 1)
		if délai > DélaiMaximum || délai <= 0 {
			délai = DélaiMaximum
		}
		c.bloquéJusq = maintenant.Add(délai)
	}
}

// purgerSiNécessaire retire les compteurs oubliés.
//
// Sans purge, les deux tables grossissent indéfiniment : une adresse source par
// machine ayant tenté un bind, ce qui est exactement ce qu'un balayage produit
// en masse. La purge est amortie plutôt que périodique, pour ne pas porter une
// goroutine de plus.
func purgerSiNécessaire() {
	maintenant := time.Now()
	if maintenant.Sub(dernierPurge) < FenêtreOubli {
		return
	}
	dernierPurge = maintenant
	for _, m := range []map[string]*compteur{parSource, parCompte} {
		for clé, c := range m {
			if maintenant.Sub(c.dernier) > FenêtreOubli && maintenant.After(c.bloquéJusq) {
				delete(m, clé)
			}
		}
	}
}
