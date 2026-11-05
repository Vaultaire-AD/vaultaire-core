package keymanagement

import (
	"database/sql"
	"fmt"
	"strings"

	"vaultaire/core/clienttype"
	"vaultaire/core/database"
	dbcertificates "vaultaire/core/database/db_certificates"
	dbschema "vaultaire/core/database/db_schema"
	"vaultaire/core/logs"
	"vaultaire/core/paquetagent"
)

// Le magasin de la rotation de pkg_signing, en base — TO-DO 207.
//
// Trois lignes de `certificates`, une par rôle (paquetagent.Role…), et la table
// des jeux publiés. La logique des trois gestes est dans paquetagent
// (rotation.go), testée sans base ; ici, seulement les lectures et écritures.
//
// La table `certificates` est partagée par le cluster : une rotation lancée
// depuis un core vaut pour tous, sans réplication.

// Noms des lignes de certificates, par rôle.
const (
	PkgSigningNextName     = "pkg_signing_next"
	PkgSigningPreviousName = "pkg_signing_previous"
)

func nomDuRole(role string) (string, error) {
	switch role {
	case paquetagent.RoleActive:
		return PkgSigningKeyName, nil
	case paquetagent.RoleSuivante:
		return PkgSigningNextName, nil
	case paquetagent.RolePrecedente:
		return PkgSigningPreviousName, nil
	}
	return "", fmt.Errorf("rôle de clé inconnu : %q", role)
}

// MagasinPaquets est le magasin en base.
type MagasinPaquets struct{}

var _ paquetagent.Magasin = MagasinPaquets{}

func (MagasinPaquets) db() (*sql.DB, error) {
	db := database.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("base indisponible")
	}
	return db, nil
}

// Cle lit une clé par son rôle.
func (MagasinPaquets) Cle(role string) (paquetagent.CleStockee, bool, error) {
	nom, err := nomDuRole(role)
	if err != nil {
		return paquetagent.CleStockee{}, false, err
	}
	cert, err := dbcertificates.GetCertificateByName(nom)
	if err != nil {
		if estCertificatIntrouvable(err) {
			return paquetagent.CleStockee{}, false, nil
		}
		return paquetagent.CleStockee{}, false, fmt.Errorf("clé %s : %w", nom, err)
	}
	if cert.PublicKeyData == nil {
		return paquetagent.CleStockee{}, false, fmt.Errorf("clé %s sans partie publique", nom)
	}
	pubs, err := paquetagent.LireClesPubliques([]byte(*cert.PublicKeyData))
	if err != nil {
		return paquetagent.CleStockee{}, false, fmt.Errorf("clé %s : %w", nom, err)
	}
	c := paquetagent.CleStockee{Publique: pubs[0]}
	if cert.PrivateKeyData != nil && *cert.PrivateKeyData != "" {
		if c.Privee, err = paquetagent.LireClePrivee([]byte(*cert.PrivateKeyData)); err != nil {
			return paquetagent.CleStockee{}, false, fmt.Errorf("clé %s : %w", nom, err)
		}
	}
	return c, true, nil
}

func (m MagasinPaquets) generer(nom, description string) (paquetagent.CleStockee, error) {
	privee, publique, err := GenerateKeyRSA(4096)
	if err != nil {
		return paquetagent.CleStockee{}, err
	}
	if err := SaveKeyPairToDB(nom, "rsa_keypair", description, privee, publique); err != nil {
		return paquetagent.CleStockee{}, err
	}
	return paquetagent.CleStockee{Publique: publique, Privee: privee}, nil
}

// GenererSuivante tire la clé suivante (geste 1).
func (m MagasinPaquets) GenererSuivante() (paquetagent.CleStockee, error) {
	c, err := m.generer(PkgSigningNextName, "Clé SUIVANTE de signature des paquets (rotation en cours, TO-DO 207)")
	if err == nil {
		logs.Write_Log("SECURITY", "keymanagement: clé suivante de signature des paquets générée (rotation)")
	}
	return c, err
}

// renommer exécute des renommages de lignes dans une transaction, chacun
// devant toucher exactement une ligne.
func (m MagasinPaquets) renommer(paires ...[2]string) error {
	db, err := m.db()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, p := range paires {
		r, err := tx.Exec(`UPDATE certificates SET name = ? WHERE name = ?`, p[1], p[0])
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("%s → %s : %w", p[0], p[1], err)
		}
		if n, _ := r.RowsAffected(); n != 1 {
			_ = tx.Rollback()
			return fmt.Errorf("%s → %s : %d ligne(s) touchée(s), 1 attendue", p[0], p[1], n)
		}
	}
	return tx.Commit()
}

// Basculer : l'active devient la précédente, la suivante l'active (geste 2).
func (m MagasinPaquets) Basculer() error {
	if err := m.renommer([2]string{PkgSigningKeyName, PkgSigningPreviousName},
		[2]string{PkgSigningNextName, PkgSigningKeyName}); err != nil {
		return err
	}
	logs.Write_Log("SECURITY", "keymanagement: signature des paquets basculée sur la nouvelle clé")
	return nil
}

func (m MagasinPaquets) effacer(noms ...string) error {
	db, err := m.db()
	if err != nil {
		return err
	}
	for _, n := range noms {
		if _, err := db.Exec(`DELETE FROM certificates WHERE name = ?`, n); err != nil {
			return fmt.Errorf("effacement de %s : %w", n, err)
		}
	}
	return nil
}

// OublierPrecedente efface l'ancienne clé (geste 3).
func (m MagasinPaquets) OublierPrecedente() error {
	if err := m.effacer(PkgSigningPreviousName); err != nil {
		return err
	}
	logs.Write_Log("SECURITY", "keymanagement: ancienne clé de signature des paquets oubliée — rotation terminée")
	return nil
}

// RemplacerCompromise : nouvelle active, plus aucune autre.
//
// La nouvelle est d'abord posée sous le nom de la suivante, puis la bascule
// se fait dans une transaction : il n'y a jamais d'instant sans clé active.
func (m MagasinPaquets) RemplacerCompromise() (paquetagent.CleStockee, error) {
	if err := m.effacer(PkgSigningNextName, PkgSigningPreviousName); err != nil {
		return paquetagent.CleStockee{}, err
	}
	c, err := m.generer(PkgSigningNextName, "Clé de signature des paquets (remplacement après compromission, TO-DO 207)")
	if err != nil {
		return paquetagent.CleStockee{}, err
	}
	if err := m.renommer([2]string{PkgSigningKeyName, PkgSigningPreviousName},
		[2]string{PkgSigningNextName, PkgSigningKeyName}); err != nil {
		return paquetagent.CleStockee{}, err
	}
	if err := m.effacer(PkgSigningPreviousName); err != nil {
		return paquetagent.CleStockee{}, err
	}
	logs.Write_Log("SECURITY", "keymanagement: clé de signature des paquets REMPLACÉE après compromission — "+
		"chaque machine doit recevoir le nouveau fichier par réinstallation")
	return c, nil
}

func (m MagasinPaquets) lireJeu(requete string, args ...any) (paquetagent.JeuStocke, bool, error) {
	db, err := m.db()
	if err != nil {
		return paquetagent.JeuStocke{}, false, err
	}
	var j paquetagent.JeuStocke
	err = db.QueryRow(requete, args...).Scan(&j.Numero, &j.Corps, &j.Enveloppe)
	switch {
	case err == sql.ErrNoRows:
		return paquetagent.JeuStocke{}, false, nil
	case err != nil:
		return paquetagent.JeuStocke{}, false, fmt.Errorf("lecture des jeux de clés : %w", err)
	}
	return j, true, nil
}

// DernierJeu rend le jeu le plus haut.
func (m MagasinPaquets) DernierJeu() (paquetagent.JeuStocke, bool, error) {
	return m.lireJeu(`SELECT numero, corps, enveloppe FROM ` + dbschema.TableJeuxCles +
		` ORDER BY numero DESC LIMIT 1`)
}

// JeuApres rend le plus petit jeu au-dessus de n.
func (m MagasinPaquets) JeuApres(n int) (paquetagent.JeuStocke, bool, error) {
	return m.lireJeu(`SELECT numero, corps, enveloppe FROM `+dbschema.TableJeuxCles+
		` WHERE numero > ? ORDER BY numero ASC LIMIT 1`, n)
}

// AjouterJeu publie un jeu. Le numéro est la clé primaire : deux cores qui
// publieraient le même ne peuvent pas réussir tous les deux.
func (m MagasinPaquets) AjouterJeu(j paquetagent.JeuStocke) error {
	db, err := m.db()
	if err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO `+dbschema.TableJeuxCles+` (numero, corps, enveloppe) VALUES (?, ?, ?)`,
		j.Numero, j.Corps, j.Enveloppe); err != nil {
		return fmt.Errorf("publication du jeu n°%d : %w", j.Numero, err)
	}
	logs.Write_Log("SECURITY", fmt.Sprintf("keymanagement: jeu de clés des paquets n°%d publié", j.Numero))
	return nil
}

// Agents : les agents LINUX. L'agent Windows ne vérifie pas de paquets
// (TO-DO 118) et ne demande pas de jeu : le compter ferait refuser toute
// bascule.
func (m MagasinPaquets) Agents() ([]paquetagent.AgentJeu, error) {
	db, err := m.db()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT computeur_id, hostname, os, agent_pkg_trust FROM id_logiciels
		WHERE logiciel_type = ?`, clienttype.Client)
	if err != nil {
		return nil, fmt.Errorf("lecture des agents : %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []paquetagent.AgentJeu
	for rows.Next() {
		var a paquetagent.AgentJeu
		var hote, os string
		if err := rows.Scan(&a.ComputeurID, &hote, &os, &a.Numero); err != nil {
			return nil, fmt.Errorf("lecture des agents : %w", err)
		}
		if strings.Contains(strings.ToLower(os), "windows") {
			continue
		}
		a.Nom = a.ComputeurID
		if strings.TrimSpace(hote) != "" {
			a.Nom = hote
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
