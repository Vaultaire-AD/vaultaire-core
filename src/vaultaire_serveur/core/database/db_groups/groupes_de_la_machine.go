package dbgroups

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database"
	"vaultaire/core/logs"
)

// GroupeDuDomaine est un groupe tel qu'une machine du parc doit le connaître.
type GroupeDuDomaine struct {
	Nom     string
	IDGroup int
}

// GroupesDesDomainesDeLaMachine rend les groupes que la machine doit créer
// localement.
//
// # Pourquoi les domaines de la machine, et pas tous les groupes
//
// Une machine d'un seul domaine n'a aucune raison de connaître les groupes des
// autres. La liste complète des groupes de l'organisation est une information de
// structure — qui existe, comment c'est découpé, combien il y a d'équipes — et
// `/etc/group` est lisible par TOUS les comptes locaux de la machine, y compris
// ceux qui n'ont rien à voir avec l'annuaire.
//
// Le chemin est donc : la machine appartient à des groupes (`logiciel_group`),
// ces groupes appartiennent à des domaines (`domain_group`), et on rend tous les
// groupes de ces domaines-là.
//
// # Ce qui n'est PAS filtré
//
// Les groupes dont la machine n'est pas membre. Ils sont annoncés quand même :
// un utilisateur qui s'y connecte peut appartenir à un groupe du domaine que la
// machine ne partage pas, et son appartenance doit pouvoir être posée. Le filtre
// porte sur le domaine, pas sur l'appartenance de la machine.
//
// # L'ordre
//
// Trié par nom. Sans tri, l'ordre dépend du plan d'exécution : la liste envoyée
// changerait d'une synchronisation à l'autre sans qu'aucun groupe ait bougé, et
// les journaux des deux côtés se rempliraient de différences qui n'en sont pas.
func GroupesDesDomainesDeLaMachine(db *sql.DB, computeurID string) ([]GroupeDuDomaine, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return nil, err
	}

	rows, err := db.Query(`
		SELECT DISTINCT g.group_name, g.id_group
		  FROM groups g
		  JOIN domain_group dg ON dg.d_id_group = g.id_group
		 WHERE dg.domain_name IN (
		       SELECT dg2.domain_name
		         FROM logiciel_group lg
		         JOIN id_logiciels l  ON l.id_logiciel = lg.d_id_logiciel
		         JOIN domain_group dg2 ON dg2.d_id_group = lg.d_id_group
		        WHERE l.computeur_id = ?
		 )
		 ORDER BY g.group_name`, computeurID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: groupes des domaines de "+computeurID+" illisibles : "+err.Error())
		return nil, fmt.Errorf("lecture des groupes de %q : %w", computeurID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []GroupeDuDomaine
	for rows.Next() {
		var g GroupeDuDomaine
		if err := rows.Scan(&g.Nom, &g.IDGroup); err != nil {
			return nil, fmt.Errorf("lecture d'un groupe : %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des groupes de %q : %w", computeurID, err)
	}
	return out, nil
}

// LigneDeGroupe met un groupe en forme pour la trame 03_09.
//
// Format « <nom>:<id_group> ». Le GID n'y figure PAS : la règle de calcul
// appartient au code des deux côtés, et le réseau ne transporte que des
// identifiants. Voir GIDDeGroupe.
//
// L'identifiant est validé ICI, à l'émission, plutôt que laissé à l'agent : un
// groupe dont l'identifiant sort de la borne ne doit pas être annoncé du tout.
// L'agent revérifie tout de même — le serveur est authentifié, pas infaillible.
//
// Rend une chaîne vide et une erreur si le groupe ne peut pas être annoncé.
func LigneDeGroupe(g GroupeDuDomaine) (string, error) {
	if g.Nom == "" {
		return "", fmt.Errorf("groupe %d sans nom", g.IDGroup)
	}
	// Le nom traverse deux formats à séparateurs : la trame, dont « : » sépare
	// le nom de l'identifiant, et `/etc/group` côté machine. Un nom qui en
	// contient décalerait toutes les colonnes suivantes.
	for _, c := range g.Nom {
		if c == ':' || c == ',' || c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			return "", fmt.Errorf("nom de groupe %q : contient un séparateur", g.Nom)
		}
	}
	if _, err := GIDDeGroupe(g.IDGroup); err != nil {
		return "", fmt.Errorf("groupe %q : %w", g.Nom, err)
	}
	return fmt.Sprintf("%s:%d", g.Nom, g.IDGroup), nil
}
