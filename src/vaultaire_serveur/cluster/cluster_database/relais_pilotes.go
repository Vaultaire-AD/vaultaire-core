package clusterdatabase

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// Les relais des proxies en base — TO-DO 141.
//
// # Deux tables, deux natures
//
//	cluster_relays        ce que le core DEMANDE : une ligne par relais
//	cluster_relay_state   une ligne par proxy : la révision de la demande, et
//	                      le dernier compte rendu du proxy
//
// La demande est de la DONNÉE : un administrateur l'a décidée, elle doit
// survivre à tout. Le compte rendu est de l'ÉTAT VIVANT, réécrit chaque
// minute par le proxy. Les garder dans la même ligne aurait fait réécrire la
// décision à chaque battement.
//
// # La clé est le PROPRIÉTAIRE, pas le nœud
//
// `cluster_nodes` oublie un nœud resté hors ligne vingt-quatre heures, et le
// recrée à son retour avec un autre identifiant. Rattachée à lui, la liste de
// relais d'un proxy éteint un week-end disparaîtrait avec — et il reviendrait
// sur son fichier, sans que personne l'ait décidé. Le propriétaire est
// l'identifiant du CLIENT : il ne change pas tant que le proxy garde son
// identité.
//
// # La révision
//
// Elle augmente d'un à chaque écriture, dans la même transaction que la liste.
// C'est elle que le proxy rapporte, et c'est par elle qu'on sait s'il applique
// ce qu'on voit à l'écran ou ce qu'il y avait avant.
//
// Elle ne REDESCEND jamais. Quand le core rend la main, c'est le drapeau
// `pilote` qui retombe, pas le compteur : remis à zéro, il redonnerait le
// numéro 1 à la liste suivante — et un proxy resté hors ligne pendant
// l'aller-retour, qui appliquait encore l'ancienne révision 1, la dirait
// « appliquée » sans l'avoir jamais reçue.

// RelaisDemandes rend la liste demandée à un proxy et l'état de cette demande.
// Si le core ne pilote pas ce proxy, la liste est vide.
func RelaisDemandes(db *sql.DB, proprietaire string) ([]clusterstorage.RelaisConfig, EtatDeLaDemande, error) {
	etat, err := etatDeLaDemande(db, proprietaire)
	if err != nil || !etat.Pilote {
		return nil, etat, err
	}

	rows, err := db.Query(`
		SELECT nom, type, ecoute, source, COALESCE(adresses, ''), port_cible,
		       delai_connexion_s, inactivite_s, max_connexions, max_par_source
		  FROM cluster_relays
		 WHERE owner_client_id = ?
		 ORDER BY position, nom`, proprietaire)
	if err != nil {
		return nil, etat, fmt.Errorf("lecture des relais demandés : %w", err)
	}
	defer rows.Close()

	var liste []clusterstorage.RelaisConfig
	for rows.Next() {
		var r clusterstorage.RelaisConfig
		var adresses string
		if err := rows.Scan(&r.Nom, &r.Type, &r.Ecoute, &r.Cibles.Source, &adresses, &r.Cibles.Port,
			&r.DelaiConnexionSecondes, &r.InactiviteSecondes, &r.MaxConnexions, &r.MaxParSource); err != nil {
			return nil, etat, fmt.Errorf("lecture des relais demandés : %w", err)
		}
		r.Cibles.Adresses = decouperAdresses(adresses)
		liste = append(liste, r)
	}
	// Une lecture interrompue rendrait une liste PARTIELLE : poussée telle
	// quelle, elle ferait fermer au proxy les relais qui manquent.
	if err := rows.Err(); err != nil {
		return nil, etat, fmt.Errorf("lecture des relais demandés : %w", err)
	}
	return liste, etat, nil
}

// EtatDeLaDemande dit où en est la demande du core pour un proxy.
type EtatDeLaDemande struct {
	// Pilote : le core a une liste pour ce proxy, et elle fait foi.
	Pilote bool
	// Revision est le compteur des écritures. Il vaut encore quelque chose
	// quand Pilote est faux — le numéro de la dernière liste retirée.
	Revision   int
	ModifiePar string
	ModifieLe  time.Time
}

// RevisionDemandee rend la révision que le proxy doit appliquer, ou ZÉRO si
// le core ne le pilote pas. C'est la valeur à comparer à ce que le proxy
// rapporte.
func (e EtatDeLaDemande) RevisionDemandee() int {
	if !e.Pilote {
		return 0
	}
	return e.Revision
}

func etatDeLaDemande(db *sql.DB, proprietaire string) (EtatDeLaDemande, error) {
	var e EtatDeLaDemande
	var par sql.NullString
	var le sql.NullTime
	err := db.QueryRow(`SELECT pilote, revision, modifie_par, modifie_le FROM cluster_relay_state WHERE owner_client_id = ?`,
		proprietaire).Scan(&e.Pilote, &e.Revision, &par, &le)
	if err == sql.ErrNoRows {
		return EtatDeLaDemande{}, nil
	}
	if err != nil {
		return EtatDeLaDemande{}, fmt.Errorf("lecture de l'état des relais : %w", err)
	}
	e.ModifiePar, e.ModifieLe = par.String, le.Time
	return e, nil
}

// EcrireRelaisDemandes remplace la liste demandée à un proxy et rend la
// nouvelle révision.
//
// Sous TRANSACTION : une écriture partielle laisserait en base une liste à
// moitié remplacée sous une révision neuve, que le proxy appliquerait en
// fermant ce qui manque.
//
// La liste doit avoir été contrôlée par clusterstorage.ValiderListeDeRelais :
// cette fonction écrit, elle ne juge pas.
func EcrireRelaisDemandes(db *sql.DB, proprietaire string, liste []clusterstorage.RelaisConfig, par string) (int, error) {
	if strings.TrimSpace(proprietaire) == "" {
		return 0, fmt.Errorf("propriétaire du nœud inconnu : relais non écrits")
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("écriture des relais : %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// La ligne d'état est créée si elle manque, puis VERROUILLÉE : deux
	// administrateurs qui enregistrent en même temps prennent chacun leur
	// révision, l'un après l'autre.
	if _, err := tx.Exec(`INSERT IGNORE INTO cluster_relay_state (owner_client_id, revision) VALUES (?, 0)`,
		proprietaire); err != nil {
		return 0, fmt.Errorf("écriture des relais : %w", err)
	}
	var revision int
	if err := tx.QueryRow(`SELECT revision FROM cluster_relay_state WHERE owner_client_id = ? FOR UPDATE`,
		proprietaire).Scan(&revision); err != nil {
		return 0, fmt.Errorf("écriture des relais : %w", err)
	}
	revision++

	if _, err := tx.Exec(`DELETE FROM cluster_relays WHERE owner_client_id = ?`, proprietaire); err != nil {
		return 0, fmt.Errorf("écriture des relais : %w", err)
	}
	for position, r := range liste {
		if _, err := tx.Exec(`
			INSERT INTO cluster_relays
			  (owner_client_id, nom, type, ecoute, source, adresses, port_cible,
			   delai_connexion_s, inactivite_s, max_connexions, max_par_source, position)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			proprietaire, r.Nom, r.Type, r.Ecoute, r.Cibles.Source, strings.Join(r.Cibles.Adresses, "\n"), r.Cibles.Port,
			r.DelaiConnexionSecondes, r.InactiviteSecondes, r.MaxConnexions, r.MaxParSource, position); err != nil {
			return 0, fmt.Errorf("écriture du relais %s : %w", r.Nom, err)
		}
	}
	if _, err := tx.Exec(`UPDATE cluster_relay_state SET pilote = TRUE, revision = ?, modifie_par = ?, modifie_le = ? WHERE owner_client_id = ?`,
		revision, par, time.Now().UTC(), proprietaire); err != nil {
		return 0, fmt.Errorf("écriture des relais : %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("écriture des relais : %w", err)
	}
	return revision, nil
}

// RendreLaMainAuFichier retire la demande du core pour un proxy : il
// réappliquera son fichier de configuration.
//
// Le drapeau `pilote` retombe et la liste est supprimée ; la révision, elle,
// AVANCE d'un — voir « La révision » en tête de fichier. Le compte rendu du
// proxy est gardé : c'est lui qui dira, au tour suivant, qu'il est revenu sur
// son fichier.
func RendreLaMainAuFichier(db *sql.DB, proprietaire, par string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("retrait des relais demandés : %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM cluster_relays WHERE owner_client_id = ?`, proprietaire); err != nil {
		return fmt.Errorf("retrait des relais demandés : %w", err)
	}
	if _, err := tx.Exec(`UPDATE cluster_relay_state SET pilote = FALSE, revision = revision + 1, modifie_par = ?, modifie_le = ? WHERE owner_client_id = ?`,
		par, time.Now().UTC(), proprietaire); err != nil {
		return fmt.Errorf("retrait des relais demandés : %w", err)
	}
	return tx.Commit()
}

// EnregistrerCompteRendu garde le dernier compte rendu d'un proxy.
//
// UNE ligne par proxy, réécrite : seul le dernier état sert, et une série
// temporelle d'un document d'un kilo-octet par minute et par proxy ne
// servirait à personne.
//
// L'écriture ne touche NI au drapeau `pilote`, NI à la révision, NI à la liste
// demandée : un proxy ne peut pas, par son compte rendu, changer ce que le
// core lui demande.
func EnregistrerCompteRendu(db *sql.DB, proprietaire, document string) error {
	_, err := db.Exec(`
		INSERT INTO cluster_relay_state (owner_client_id, revision, rapport, rapport_le)
		VALUES (?, 0, ?, ?)
		ON DUPLICATE KEY UPDATE rapport = VALUES(rapport), rapport_le = VALUES(rapport_le)`,
		proprietaire, document, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("enregistrement du compte rendu des relais : %w", err)
	}
	return nil
}

// DernierCompteRendu rend le dernier compte rendu d'un proxy, ou nil s'il n'en
// a jamais envoyé — ou si celui qu'on garde est illisible.
func DernierCompteRendu(db *sql.DB, proprietaire string) (*clusterstorage.CompteRenduRelais, error) {
	var document sql.NullString
	var le sql.NullTime
	err := db.QueryRow(`SELECT rapport, rapport_le FROM cluster_relay_state WHERE owner_client_id = ?`,
		proprietaire).Scan(&document, &le)
	if err == sql.ErrNoRows || (err == nil && !document.Valid) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lecture du compte rendu des relais : %w", err)
	}
	c, err := clusterstorage.DecoderCompteRendu(document.String)
	if err != nil {
		// Écrit par un proxy : un document illisible vaut « rien de connu »,
		// pas une page d'état de cluster en erreur.
		return nil, nil
	}
	c.Recu = le.Time
	return &c, nil
}

// ProprietaireDuNoeud rend l'identifiant du client qui possède un nœud.
func ProprietaireDuNoeud(db *sql.DB, hostname string) (string, error) {
	var proprietaire string
	err := db.QueryRow(`SELECT owner_client_id FROM cluster_nodes WHERE hostname = ?`, hostname).Scan(&proprietaire)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("nœud %q introuvable dans le cluster", hostname)
	}
	if err != nil {
		return "", fmt.Errorf("lecture du nœud %q : %w", hostname, err)
	}
	return proprietaire, nil
}

func decouperAdresses(brut string) []string {
	var out []string
	for _, a := range strings.Split(brut, "\n") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}
