package dbldap

import (
	"database/sql"
	"fmt"
	"strings"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// tailleLotGroupes borne le nombre de noms par requête.
//
// MariaDB accepte beaucoup de paramètres, pas un nombre illimité, et une
// requête à dix mille marqueurs est lente à préparer. Même valeur, et même
// raison, que pour GetUsersByUsernames.
const tailleLotGroupes = 500

// GetGroupsWithUsersByNames lit plusieurs groupes, avec leurs membres, en lot.
//
// # Ce qui a changé — TO-DO 131
//
// La fonction bouclait sur les noms et lançait UNE requête par groupe. Le
// résolveur LDAP l'appelle avec tous les groupes d'un domaine : 500 groupes,
// 500 allers-retours — par recherche, alors que son propre commentaire
// annonçait une lecture en lot. Le N+1 par utilisateur avait été retiré ;
// celui par groupe était resté.
//
// La requête est la même, avec un IN à la place de l'égalité. Les noms restent
// des paramètres liés, jamais concaténés.
//
// # Ce qui n'a PAS changé
//
//   - un groupe SANS MEMBRE n'est pas rendu : les jointures sont internes,
//     comme avant. Ce n'est pas un oubli à corriger ici — `groupOfNames` exige
//     au moins un `member` (RFC 4519 §3.5), et un groupe vide n'a pas de forme
//     valide à servir ;
//   - un nom inconnu n'est pas une erreur : il manque simplement au résultat ;
//   - les groupes sortent dans l'ordre des noms REÇUS. Le résolveur construit
//     ses entrées dans cet ordre, et une recherche doit rendre deux fois la même
//     chose.
//
// Ce qui devient déterministe : l'ordre des membres d'un groupe, trié par nom.
// Il dépendait du plan d'exécution de la base.
func GetGroupsWithUsersByNames(db *sql.DB, groupNames []string) ([]ldapstorage.Group, error) {
	noms := sansDoublons(groupNames)
	if len(noms) == 0 {
		return []ldapstorage.Group{}, nil
	}

	var lignes []ligneDeGroupe
	for début := 0; début < len(noms); début += tailleLotGroupes {
		fin := début + tailleLotGroupes
		if fin > len(noms) {
			fin = len(noms)
		}
		lot, err := lireLotDeGroupes(db, noms[début:fin])
		if err != nil {
			return nil, err
		}
		lignes = append(lignes, lot...)
	}
	return assemblerGroupes(lignes, noms), nil
}

// GetGroupWithUsersByName lit UN groupe et ses membres. Rend nil, sans erreur,
// si le groupe n'existe pas ou n'a aucun membre.
//
// Elle passe par la lecture en lot : il n'y a plus qu'une requête à tenir à
// jour quand une colonne s'ajoute — `entry_uuid` avait dû être écrite deux
// fois.
func GetGroupWithUsersByName(db *sql.DB, groupName string) (*ldapstorage.Group, error) {
	if strings.TrimSpace(groupName) == "" {
		return nil, fmt.Errorf("nom de groupe vide")
	}
	groupes, err := GetGroupsWithUsersByNames(db, []string{groupName})
	if err != nil {
		return nil, err
	}
	if len(groupes) == 0 {
		return nil, nil
	}
	return &groupes[0], nil
}

// ligneDeGroupe est une ligne de la jointure : un membre d'un groupe.
type ligneDeGroupe struct {
	groupe, domaine, membre string
	creeLe, modifieLe       string
	entryUUID               string
}

// lireLotDeGroupes exécute la requête pour un lot de noms.
func lireLotDeGroupes(db *sql.DB, noms []string) ([]ligneDeGroupe, error) {
	marqueurs := strings.TrimSuffix(strings.Repeat("?,", len(noms)), ",")
	args := make([]any, len(noms))
	for i, n := range noms {
		args[i] = n
	}

	rows, err := db.Query(`
		SELECT g.group_name, dg.domain_name, u.username, g.created_at, g.updated_at,
		       COALESCE(g.entry_uuid, '')
		FROM groups g
		JOIN domain_group dg ON dg.d_id_group = g.id_group
		JOIN users_group ug ON ug.d_id_group = g.id_group
		JOIN users u ON u.id_user = ug.d_id_user
		WHERE g.group_name IN (`+marqueurs+`)
		ORDER BY g.group_name, u.username`, args...)
	if err != nil {
		return nil, fmt.Errorf("lecture des groupes et de leurs membres : %w", err)
	}
	defer rows.Close()

	var lignes []ligneDeGroupe
	for rows.Next() {
		var l ligneDeGroupe
		if err := rows.Scan(&l.groupe, &l.domaine, &l.membre, &l.creeLe, &l.modifieLe, &l.entryUUID); err != nil {
			return nil, fmt.Errorf("lecture d'une ligne de groupe : %w", err)
		}
		lignes = append(lignes, l)
	}
	// rows.Err() distingue « la lecture est terminée » de « la lecture s'est
	// interrompue » : sans lui, une coupure rend des groupes amputés de leurs
	// derniers membres, présentés comme complets.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des groupes : %w", err)
	}
	return lignes, nil
}

// assemblerGroupes regroupe les lignes par groupe et les rend dans l'ordre des
// noms demandés.
//
// Séparée de la lecture pour être éprouvée sans base : c'est ici que se joue
// ce que la boucle d'avant garantissait sans y penser — un groupe par nom, dans
// l'ordre, chaque membre une fois.
//
// Un groupe que la base rend sous un nom qui ne figure pas tel quel dans la
// liste — la comparaison SQL ignore la casse, celle d'une table Go non — n'est
// pas perdu : il sort à la suite, dans l'ordre de lecture.
func assemblerGroupes(lignes []ligneDeGroupe, ordre []string) []ldapstorage.Group {
	parNom := make(map[string]*ldapstorage.Group, len(ordre))
	var lus []string // noms dans l'ordre de première lecture
	for _, l := range lignes {
		g, connu := parNom[l.groupe]
		if !connu {
			g = &ldapstorage.Group{
				GroupName:   l.groupe,
				DomainName:  l.domaine,
				Created_at:  l.creeLe,
				Modified_at: l.modifieLe,
				EntryUUID:   l.entryUUID,
				Users:       []string{},
			}
			parNom[l.groupe] = g
			lus = append(lus, l.groupe)
		}
		g.Users = append(g.Users, l.membre)
	}

	groupes := make([]ldapstorage.Group, 0, len(parNom))
	rendus := make(map[string]struct{}, len(parNom))
	for _, nom := range ordre {
		if g, trouvé := parNom[nom]; trouvé {
			if _, déjà := rendus[nom]; !déjà {
				groupes = append(groupes, *g)
				rendus[nom] = struct{}{}
			}
		}
	}
	for _, nom := range lus {
		if _, déjà := rendus[nom]; !déjà {
			groupes = append(groupes, *parNom[nom])
			rendus[nom] = struct{}{}
		}
	}
	return groupes
}

// sansDoublons retire les noms vides et répétés, en gardant l'ordre.
func sansDoublons(noms []string) []string {
	out := make([]string, 0, len(noms))
	vus := make(map[string]struct{}, len(noms))
	for _, n := range noms {
		if strings.TrimSpace(n) == "" {
			continue
		}
		if _, déjà := vus[n]; déjà {
			continue
		}
		vus[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
