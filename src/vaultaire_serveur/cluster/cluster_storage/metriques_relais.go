package clusterstorage

import (
	"fmt"
	"time"
)

// Ce qu'un proxy remonte de ses relais — TO-DO 108.
//
// # Pourquoi la structure est ici et pas dans le paquet de lecture
//
// Elle est décodée par `cluster_database`, portée par `Node`, et lue par la
// ligne de commande comme par l'interface web. La poser près de la lecture
// aurait obligé l'affichage à importer la base pour connaître un type.
//
// # Le format vient du proxy, pas de nous
//
// Les étiquettes JSON sont celles que le proxy écrit dans la colonne `extra` de
// `proxy_metrics`. Les deux modules ne partagent aucun code : c'est un format de
// PROTOCOLE, au même titre qu'un numéro de trame, et le changer d'un seul côté
// vide silencieusement la vue.
//
// Un champ absent vaut zéro — c'est ce qui permet au proxy d'en ajouter un sans
// qu'un core resté en arrière ne refuse la mesure entière.

// MetriquesRelais agrège les compteurs de tous les relais d'un nœud.
type MetriquesRelais struct {
	Actives           int64          `json:"actives"`
	Total             int64          `json:"total"`
	Refusees          int64          `json:"refusees"`
	Rejetees          int64          `json:"rejetees"`
	OctetsMontants    int64          `json:"octets_montants"`
	OctetsDescendants int64          `json:"octets_descendants"`
	Relais            []RelaisMesure `json:"relais"`

	// Mesure est l'heure d'enregistrement de la ligne, pas celle du relevé.
	//
	// L'écart est d'un aller-retour réseau. Elle sert à dire DEPUIS QUAND on
	// regarde ces chiffres : un compteur de connexions actives vieux d'une
	// heure ne décrit plus rien, et l'afficher sans son âge se lit comme un
	// état courant.
	Mesure time.Time `json:"-"`
}

// RelaisMesure est le détail d'un relais.
//
// Un proxy en porte plusieurs — Ducky, HTTPS, LDAP. L'agrégat dit qu'il refuse ;
// seul le détail dit lequel.
type RelaisMesure struct {
	Nom               string `json:"nom"`
	Type              string `json:"type"`
	Ecoute            string `json:"ecoute"`
	Actives           int64  `json:"actives"`
	Total             int64  `json:"total"`
	Refusees          int64  `json:"refusees"`
	Rejetees          int64  `json:"rejetees"`
	OctetsMontants    int64  `json:"octets_ms"`
	OctetsDescendants int64  `json:"octets_ds"`
}

// Octets rend le trafic cumulé des deux sens.
func (m MetriquesRelais) Octets() int64 { return m.OctetsMontants + m.OctetsDescendants }

// Ecartees rend le nombre de connexions qui n'ont pas été relayées.
//
// Les deux causes ensemble : « aucune cible joignable » et « plafond atteint ».
// Elles se règlent différemment, et le détail par relais les sépare — mais dans
// une vue d'ensemble, ce qui compte est qu'une connexion n'est pas passée.
func (m MetriquesRelais) Ecartees() int64 { return m.Refusees + m.Rejetees }

// TraficLisible rend le trafic cumulé en unités binaires.
//
// Une MÉTHODE, parce que les gabarits web n'appellent pas de fonction de paquet :
// sans elle, la page devrait recevoir une chaîne préformatée, et le formatage
// vivrait à deux endroits.
func (m MetriquesRelais) TraficLisible() string { return OctetsLisibles(m.Octets()) }

// TraficLisible rend le trafic d'un relais, pour la même raison.
func (r RelaisMesure) TraficLisible() string {
	return OctetsLisibles(r.OctetsMontants + r.OctetsDescendants)
}

// Ecartees rend, pour un relais, les connexions qui ne sont pas passées.
func (r RelaisMesure) Ecartees() int64 { return r.Refusees + r.Rejetees }

// OctetsLisibles rend le trafic en unités binaires.
//
// Un proxy de parc dépasse le gigaoctet en une journée : afficher le nombre brut
// demanderait de compter les chiffres pour savoir s'il faut s'en inquiéter.
//
// Une décimale et pas deux : la colonne répond à « est-ce beaucoup », pas à
// « combien exactement » — le nombre exact est dans la base.
func OctetsLisibles(n int64) string {
	const unite = 1024
	if n < unite {
		return fmt.Sprintf("%d o", n)
	}
	div, exp := int64(unite), 0
	for reste := n / unite; reste >= unite; reste /= unite {
		div *= unite
		exp++
	}
	// La virgule est calculée en entiers : passer par un flottant pour une
	// seule décimale ferait afficher « 1,0 Gio » pour 1 073 741 823 octets,
	// c'est-à-dire arrondirait vers le haut un seuil qu'on n'a pas atteint.
	return fmt.Sprintf("%d,%d %cio", n/div, (n%div)*10/div, "KMGTPE"[exp])
}
