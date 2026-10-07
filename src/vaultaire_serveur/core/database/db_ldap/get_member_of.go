package dbldap

import (
	"database/sql"
	"fmt"
	"strings"

	"vaultaire/core/database"
)

// Les groupes des comptes — ce dont LDAP fait `memberOf`.
//
// # Une seule lecture, pour les deux chemins (TO-DO 155)
//
// `memberOf` se composait de deux façons selon la recherche :
//
//   - une recherche `base` sur le DN d'un compte lisait TOUS ses groupes, par
//     GetMemberOfByUsername ;
//   - une recherche `one` ou `sub` le déduisait des groupes qu'elle venait de
//     CHARGER — ceux du domaine demandé et de ses sous-domaines.
//
// Le même compte, lu par le même appelant, n'avait donc pas le même `memberOf`
// selon la base de la recherche : ses groupes situés AU-DESSUS ou À CÔTÉ de
// cette base manquaient. Rien ne fuyait ; il manquait des valeurs. Mais une
// application synchronisée sur un sous-domaine en concluait qu'un compte
// avait quitté un groupe du domaine parent, et pouvait lui retirer les droits
// qui vont avec.
//
// Les deux chemins lisent maintenant ici. Ce que l'appelant n'a pas le droit
// de lire est retiré ensuite, compte par compte, par le contrôle d'accès
// (TO-DO 132) — sur le domaine que chaque ligne porte.
//
// # En lot
//
// Une recherche `sub` rend des milliers de comptes : une requête par compte
// ramènerait le N+1 que le point 131 a retiré. Les noms partent par lots,
// comme pour GetUsersByUsernames.

// tailleLotAppartenances borne le nombre de noms par requête. Même valeur, et
// même raison, que pour les deux autres lectures en lot de ce paquet.
const tailleLotAppartenances = 500

// Appartenances porte les groupes de plusieurs comptes.
//
// La clé est le nom du compte EN MINUSCULES : la base compare sans la casse,
// une table Go non. Passer par De évite d'avoir à s'en souvenir.
type Appartenances map[string][]GroupDomain

// De rend les groupes d'un compte, triés par nom de groupe puis par domaine.
// Un compte absent n'a aucun groupe — ce n'est pas une erreur.
func (a Appartenances) De(username string) []GroupDomain {
	return a[strings.ToLower(strings.TrimSpace(username))]
}

// ligneDAppartenance est une ligne rendue par la base.
type ligneDAppartenance struct {
	compte, groupe, domaine string
}

// GetMemberOfByUsernames rend les groupes de plusieurs comptes, chacun avec son
// domaine — TOUS leurs groupes, quel que soit le domaine.
func GetMemberOfByUsernames(db *sql.DB, usernames []string) (Appartenances, error) {
	noms := sansDoublons(usernames)
	if len(noms) == 0 {
		return Appartenances{}, nil
	}
	for _, n := range noms {
		if err := database.SanitizeIdentifier(n); err != nil {
			return nil, err
		}
	}

	var lignes []ligneDAppartenance
	for début := 0; début < len(noms); début += tailleLotAppartenances {
		fin := début + tailleLotAppartenances
		if fin > len(noms) {
			fin = len(noms)
		}
		lot, err := lireLotDAppartenances(db, noms[début:fin])
		if err != nil {
			return nil, err
		}
		lignes = append(lignes, lot...)
	}
	return assemblerAppartenances(lignes), nil
}

// GetMemberOfByUsername rend les groupes d'UN compte, avec leur domaine.
//
// Elle passe par la lecture en lot : c'est ce qui garantit qu'une recherche
// `base` et une recherche `sub` rendent le même `memberOf`, dans le même
// ordre — il n'y a plus qu'une requête.
func GetMemberOfByUsername(db *sql.DB, username string) ([]GroupDomain, error) {
	tous, err := GetMemberOfByUsernames(db, []string{username})
	if err != nil {
		return nil, fmt.Errorf("lecture des groupes de %s : %w", username, err)
	}
	return tous.De(username), nil
}

func lireLotDAppartenances(db *sql.DB, noms []string) ([]ligneDAppartenance, error) {
	marqueurs := strings.TrimSuffix(strings.Repeat("?,", len(noms)), ",")
	args := make([]any, len(noms))
	for i, n := range noms {
		args[i] = n
	}

	// GROUP BY : un groupe rattaché deux fois au même domaine ne compte qu'une
	// fois. ORDER BY : l'ordre dépendait du plan d'exécution, et une recherche
	// rejouée doit rendre la même chose.
	rows, err := db.Query(`
		SELECT u.username, g.group_name, dg.domain_name
		FROM users u
		JOIN users_group ug ON u.id_user = ug.d_id_user
		JOIN groups g ON ug.d_id_group = g.id_group
		JOIN domain_group dg ON dg.d_id_group = g.id_group
		WHERE u.username IN (`+marqueurs+`)
		GROUP BY u.username, g.group_name, dg.domain_name
		ORDER BY u.username, g.group_name, dg.domain_name`, args...)
	if err != nil {
		return nil, fmt.Errorf("lecture des appartenances : %w", err)
	}
	defer rows.Close()

	var lignes []ligneDAppartenance
	for rows.Next() {
		var l ligneDAppartenance
		if err := rows.Scan(&l.compte, &l.groupe, &l.domaine); err != nil {
			return nil, fmt.Errorf("lecture d'une ligne d'appartenance : %w", err)
		}
		lignes = append(lignes, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des appartenances : %w", err)
	}
	return lignes, nil
}

// assemblerAppartenances regroupe les lignes par compte.
//
// Pure, pour s'éprouver sans base. L'ordre des groupes d'un compte est celui
// des lignes — la requête les trie —, et un doublon exact est écarté : deux
// lots ne se recouvrent pas, mais rien ne doit dépendre de cette promesse.
func assemblerAppartenances(lignes []ligneDAppartenance) Appartenances {
	out := make(Appartenances)
	vus := make(map[string]struct{}, len(lignes))
	for _, l := range lignes {
		compte := strings.ToLower(strings.TrimSpace(l.compte))
		if compte == "" || l.groupe == "" {
			continue
		}
		cle := compte + "\x00" + l.groupe + "\x00" + l.domaine
		if _, déjà := vus[cle]; déjà {
			continue
		}
		vus[cle] = struct{}{}
		out[compte] = append(out[compte], GroupDomain{GroupName: l.groupe, DomainName: l.domaine})
	}
	return out
}
