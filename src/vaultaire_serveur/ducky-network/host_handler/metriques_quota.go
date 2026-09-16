package hosthandler

import (
	"sync"
	"time"

	"vaultaire/core/logs"
)

// Débit maximal de métriques par nœud.
//
// # Ce que ce quota protège, et ce qu'il ne protège pas
//
// Un nœud authentifié pouvait émettre autant de trames 04_05 qu'il voulait, et
// chacune insérait une ligne. Depuis que la ligne porte le nom du DEMANDEUR, ce
// n'est plus une usurpation — mais c'est une saturation de table par un client
// légitime au sens du protocole.
//
// Le quota ne défend donc que d'un nœud compromis ou déréglé. C'est peu, et
// c'est suffisant : rien d'autre ne borne cette écriture, et la table n'a pas de
// taille maximale.
//
// # Pourquoi PAS core/auth/ratelimit
//
// Ce paquet-là freine la force brute sur les mots de passe. Sa logique tout
// entière — trois essais gratuits, échéance qui double, oubli après un quart
// d'heure, deux compteurs croisés compte/source — répond à « ralentir quelqu'un
// qui devine ». Il se pilote par `Echec` et `Reussite`.
//
// Une métrique n'échoue jamais : chaque appel est une écriture légitime. Le
// réutiliser voudrait dire appeler `Echec` sur chaque métrique acceptée, ce qui
// inverse le sens de son API — et importerait une escalade qui punirait
// progressivement un nœud simplement bavard.
//
// Ce qu'il faut ici est un plafond, pas un frein. Ce sont deux problèmes
// différents, et les fondre dans un paquet rendrait les deux moins lisibles.
//
// # Une FENÊTRE FIXE, pas un seau à jetons
//
// Le seau à jetons lisserait mieux les rafales. Il demande une décroissance
// continue, donc un calcul à chaque appel et un état plus riche.
//
// La fenêtre fixe a un défaut connu : un nœud peut émettre le quota en fin de
// fenêtre et autant au début de la suivante, soit le double sur un court
// intervalle. C'est sans conséquence ici — on borne la croissance d'une table,
// pas une latence — et l'implémentation tient en vingt lignes qu'on relit
// entièrement.
//
// # Les compteurs vivent EN MÉMOIRE, donc par core
//
// Un nœud qui répartit ses envois sur N cores obtient N fois le quota. Même
// compromis que `ratelimit`, et pour la même raison : écrire un compteur en base
// à chaque métrique ferait payer à la base précisément ce qu'on cherche à lui
// éviter.

// Barème du quota.
//
// Des variables et non des constantes : les tests déplacent la fenêtre pour ne
// pas attendre réellement, et un exploitant peut durcir au démarrage.
var (
	// QuotaMetriquesParFenetre : nombre de métriques acceptées par nœud et par
	// fenêtre.
	//
	// 60 par minute, soit une par seconde et par nœud. Très large pour un usage
	// normal — le battement de cœur lui-même est à 20 secondes — et suffisant
	// pour couper net une inondation.
	QuotaMetriquesParFenetre = 60

	// FenetreQuotaMetriques est la durée de la fenêtre.
	FenetreQuotaMetriques = time.Minute

	// SilenceJournalQuota borne la fréquence du message de dépassement.
	//
	// PIÈGE ÉVITÉ : journaliser chaque métrique refusée déplacerait l'inondation
	// de la table vers le fichier de journal — le même défaut, sur un support qui
	// tolère encore moins bien. Une ligne par nœud et par intervalle suffit à
	// savoir que cela dure.
	SilenceJournalQuota = 5 * time.Minute
)

// maintenantQuota est indirect pour que les tests avancent le temps.
var maintenantQuota = time.Now

type fenetreMetriques struct {
	debut          time.Time
	compte         int
	refuses        int
	dernierJournal time.Time
}

var (
	quotaMu       sync.Mutex
	quotaParNoeud = map[string]*fenetreMetriques{}
)

// AutoriseMetrique dit si une métrique de ce nœud peut être enregistrée.
//
// Rend `false` quand le quota est atteint. L'appelant doit alors ABANDONNER la
// métrique sans punir le nœud — voir handleProxyMetrics.
func AutoriseMetrique(proprietaire string) bool {
	maintenant := maintenantQuota()

	quotaMu.Lock()
	defer quotaMu.Unlock()

	f, connu := quotaParNoeud[proprietaire]
	if !connu || maintenant.Sub(f.debut) >= FenetreQuotaMetriques {
		// Fenêtre neuve. On journalise ce que la précédente a refusé, s'il y a
		// lieu et si l'on n'a pas parlé trop récemment.
		if connu && f.refuses > 0 && maintenant.Sub(f.dernierJournal) >= SilenceJournalQuota {
			logs.Write_Log("WARNING",
				"metriques: "+proprietaire+" dépasse le quota — "+
					itoa(f.refuses)+" métrique(s) abandonnée(s) sur la dernière fenêtre")
			f.dernierJournal = maintenant
		}
		dernier := time.Time{}
		if connu {
			dernier = f.dernierJournal
		}
		quotaParNoeud[proprietaire] = &fenetreMetriques{
			debut: maintenant, compte: 1, dernierJournal: dernier,
		}
		purgerQuotaSiNecessaire(maintenant)
		return true
	}

	if f.compte >= QuotaMetriquesParFenetre {
		f.refuses++
		return false
	}
	f.compte++
	return true
}

// purgerQuotaSiNecessaire retire les nœuds qui n'émettent plus.
//
// Sans cela, la carte garderait une entrée par nœud ayant jamais émis une
// métrique — une fuite lente, sur un serveur qui tourne des mois.
//
// Appelée depuis l'ouverture d'une fenêtre, donc sous le verrou et rarement.
func purgerQuotaSiNecessaire(maintenant time.Time) {
	if len(quotaParNoeud) < 256 {
		return
	}
	for cle, f := range quotaParNoeud {
		if maintenant.Sub(f.debut) > 10*FenetreQuotaMetriques {
			delete(quotaParNoeud, cle)
		}
	}
}

// ReinitialiserQuotaMetriques vide les compteurs. Réservé aux tests.
func ReinitialiserQuotaMetriques() {
	quotaMu.Lock()
	defer quotaMu.Unlock()
	quotaParNoeud = map[string]*fenetreMetriques{}
}

// itoa évite d'importer strconv pour une seule conversion dans un message.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var chiffres []byte
	for n > 0 {
		chiffres = append([]byte{byte('0' + n%10)}, chiffres...)
		n /= 10
	}
	return string(chiffres)
}
