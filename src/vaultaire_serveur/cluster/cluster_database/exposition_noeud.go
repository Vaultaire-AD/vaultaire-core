package clusterdatabase

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// Écriture des décisions d'EXPLOITATION sur un nœud.
//
// # Ce qui distingue ces colonnes des autres
//
// `cluster_nodes` mélange deux natures. La plupart des colonnes sont des FAITS
// déclarés par le nœud — hostname, adresse vue de lui-même, port d'écoute,
// version, empreinte — et il les réécrit à chaque enregistrement.
//
// Quatre ne sont pas de cette nature :
//
//	adresse_publique     par où les agents le joignent
//	port_public          idem
//	priorite             dans quel ordre il est servi
//	expose_aux_agents    figure-t-il dans la liste
//
// Ce sont des décisions prises par un administrateur, et le nœud n'a pas de quoi
// les former : derrière une redirection, il ne voit pas l'adresse par laquelle
// on l'atteint, et il ne connaît pas non plus la place qu'on veut lui donner
// dans le parc.
//
// C'est pourquoi `RegisterNode` ne les touche PAS. Les y inclure ferait qu'un
// nœud sorti de la rotation pour maintenance y rentrerait seul à son prochain
// redémarrage — au moment précis où quelqu'un le manipule — et qu'une adresse
// publique déclarée serait écrasée par la vue interne du nœud.
//
// # Pourquoi une mise à jour PARTIELLE
//
// La ligne de commande règle un champ à la fois ; le formulaire web les envoie
// tous. Une fonction qui écrirait toujours les quatre obligerait la première à
// relire la ligne et à repasser les trois autres — et le jour où l'une serait
// oubliée, régler une priorité remettrait un nœud en rotation en silence.

// ExpositionNoeud décrit les champs à écrire. Un pointeur nul signifie
// « ne pas toucher à ce champ », ce qu'une valeur zéro ne saurait pas dire :
// l'adresse vide et le port zéro sont des valeurs légitimes, qui retirent la
// déclaration.
type ExpositionNoeud struct {
	AdressePublique *string
	PortPublic      *int
	Priorite        *int
	ExposeAuxAgents *bool
}

// Vide indique qu'aucun champ n'est à écrire.
func (e ExpositionNoeud) Vide() bool {
	return e.AdressePublique == nil && e.PortPublic == nil &&
		e.Priorite == nil && e.ExposeAuxAgents == nil
}

// ErrNoeudInconnu signale un hostname qui ne correspond à aucune ligne.
var ErrNoeudInconnu = errors.New("nœud inconnu du cluster")

// MettreAJourExposition écrit les champs demandés sur le nœud désigné.
//
// Le nœud est désigné par son HOSTNAME, qui est ce qu'un administrateur voit
// dans les vues — et non par son propriétaire, qui est un identifiant technique,
// ni par son identifiant de ligne, qui change si la table est reconstruite.
func MettreAJourExposition(db *sql.DB, hostname string, champs ExpositionNoeud) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	nom := strings.TrimSpace(hostname)
	if nom == "" {
		return fmt.Errorf("nom de nœud requis")
	}
	if champs.Vide() {
		// Refusé plutôt qu'ignoré. Une commande qui ne demande rien est une
		// commande mal tapée, et lui répondre « c'est fait » ferait croire à un
		// réglage qui n'a pas eu lieu.
		return fmt.Errorf("aucun champ à modifier")
	}

	var (
		sets    []string
		valeurs []any
	)
	if champs.AdressePublique != nil {
		propre, err := clusterstorage.ValiderAdressePublique(*champs.AdressePublique)
		if err != nil {
			return err
		}
		sets = append(sets, "adresse_publique = ?")
		valeurs = append(valeurs, propre)
	}
	if champs.PortPublic != nil {
		if *champs.PortPublic < 0 || *champs.PortPublic > 65535 {
			return fmt.Errorf("port invalide : %d est hors de 0-65535", *champs.PortPublic)
		}
		sets = append(sets, "port_public = ?")
		valeurs = append(valeurs, *champs.PortPublic)
	}
	if champs.Priorite != nil {
		// Négatif refusé : zéro vaut déjà « sans préférence » et se range APRÈS
		// les valeurs explicites. Une priorité négative se rangerait donc avant
		// tout, y compris avant ce qu'on a explicitement mis en tête — l'inverse
		// de ce que la saisie laisse attendre.
		if *champs.Priorite < 0 {
			return fmt.Errorf("priorité invalide : %d est négative (0 vaut « sans préférence »)",
				*champs.Priorite)
		}
		sets = append(sets, "priorite = ?")
		valeurs = append(valeurs, *champs.Priorite)
	}
	if champs.ExposeAuxAgents != nil {
		sets = append(sets, "expose_aux_agents = ?")
		valeurs = append(valeurs, *champs.ExposeAuxAgents)
	}

	// Les fragments de `sets` sont des constantes de CE fichier : aucune valeur
	// venue de l'appelant n'entre dans le texte de la requête, seulement dans
	// les paramètres liés.
	requete := "UPDATE cluster_nodes SET " + strings.Join(sets, ", ") + " WHERE hostname = ?"
	valeurs = append(valeurs, nom)

	res, err := db.Exec(requete, valeurs...)
	if err != nil {
		return fmt.Errorf("mise à jour du nœud %s : %w", nom, err)
	}

	// Zéro ligne touchée ne se lit PAS comme « nœud inconnu ».
	//
	// MySQL rend zéro quand l'UPDATE ne change rien — cas ordinaire d'un réglage
	// réappliqué à l'identique. Conclure « inconnu » ferait échouer la commande
	// la plus banale qui soit : régler un nœud sur la valeur qu'il a déjà.
	//
	// L'existence se vérifie donc séparément, et seulement dans ce cas.
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		var existe int
		err := db.QueryRow(`SELECT COUNT(*) FROM cluster_nodes WHERE hostname = ?`, nom).Scan(&existe)
		if err != nil {
			return fmt.Errorf("vérification du nœud %s : %w", nom, err)
		}
		if existe == 0 {
			return fmt.Errorf("%w : %q", ErrNoeudInconnu, nom)
		}
	}

	return nil
}

// NoeudParHostname relit un nœud par son nom.
//
// Sert à rendre l'état après écriture, et à le lire avant pour le journaliser :
// « X est passé de Y à Z » se retrouve six mois plus tard, « X vaut Z » ne dit
// pas ce qui a changé.
func NoeudParHostname(db *sql.DB, hostname string) (clusterstorage.Node, error) {
	var n clusterstorage.Node
	if db == nil {
		return n, fmt.Errorf("connexion base indisponible")
	}

	err := db.QueryRow(`
		SELECT id_node, hostname, fqdn, ip_address, role, status, version_code,
		       capabilities, last_heartbeat, ducky_port, priorite, expose_aux_agents,
		       key_fingerprint, sdk_version, adresse_publique, port_public
		  FROM cluster_nodes WHERE hostname = ?`, strings.TrimSpace(hostname)).Scan(
		&n.ID, &n.Hostname, &n.FQDN, &n.IPAddress, &n.Role, &n.Status, &n.VersionCode,
		&n.Capabilities, &n.LastHeartbeat, &n.Port, &n.Priorite, &n.ExposeAuxAgents,
		&n.Empreinte, &n.VersionSDK, &n.AdressePublique, &n.PortPublic)
	if errors.Is(err, sql.ErrNoRows) {
		return n, fmt.Errorf("%w : %q", ErrNoeudInconnu, hostname)
	}
	if err != nil {
		return n, fmt.Errorf("lecture du nœud %s : %w", hostname, err)
	}
	return n, nil
}
