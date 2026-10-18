// Package miseajourmanager porte les trames de la catégorie 09 côté core —
// l'ordre de mise à jour des agents (TO-DO 115). La décision est dans
// core/miseajour ; ici, le réseau et la base.
package miseajourmanager

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	dbsettings "vaultaire/core/database/db_settings"
	"vaultaire/core/logs"
	"vaultaire/core/miseajour"
	"vaultaire/core/paquetagent"
	"vaultaire/core/parcversion"
	"vaultaire/core/storage"
	keymanagement "vaultaire/ducky-network/key_management"
	"vaultaire/ducky-network/trame"
)

// Trame_Manager route les sous-ordres de la catégorie 09.
func Trame_Manager(t storage.Trames_struct_client, _ *storage.DuckySession) string {
	if len(t.Message_Order) < 2 {
		logs.Write_Log("WARNING", "miseajour: trame 09 sans sous-ordre")
		return ""
	}
	switch t.Message_Order[1] {
	case "01":
		return repondreALaDemande(t)
	case "04":
		return recevoirLeCompteRendu(t)
	case "07":
		return recevoirLaConfiguration(t)
	case "09":
		return servirLeJeuDeCles(t)
	case "02", "03", "05", "06", "08", "10":
		logs.Write_Log("WARNING", fmt.Sprintf(
			"miseajour: sous-ordre 09_%s inattendu en réception serveur (client %s)",
			t.Message_Order[1], t.ClientSoftwareID))
		return ""
	}
	logs.Write_Log("WARNING", "miseajour: sous-ordre 09_"+t.Message_Order[1]+" inconnu")
	return ""
}

// lireSituation : ce que la décision demande, pour une machine. Remplaçable
// par les tests.
var lireSituation = func(computeurID string) (miseajour.Situation, error) {
	db := database.GetDatabase()
	a, err := dbclients.AgentEtCiblesDe(db, computeurID)
	if err != nil {
		return miseajour.Situation{}, err
	}
	parc, depot, err := reglagesDuParc()
	if err != nil {
		return miseajour.Situation{}, err
	}
	return situationDe(a, parc, depot), nil
}

// reglagesDuParc lit la cible du parc et le dépôt nommé dans les ordres.
func reglagesDuParc() (parc, depot string, err error) {
	db := database.GetDatabase()
	if parc, _, err = dbsettings.GetString(db, parcversion.CleReglageParc); err != nil {
		return "", "", err
	}
	if depot, _, err = dbsettings.GetString(db, miseajour.CleReglageDepot); err != nil {
		return "", "", err
	}
	if depot != "" {
		if d, errD := miseajour.NormaliserDepot(depot); errD == nil {
			depot = d
		} else {
			logs.Write_Log("WARNING", "miseajour: dépôt réglé illisible, « "+miseajour.DepotParDefaut+
				" » retenu : "+errD.Error())
			depot = ""
		}
	}
	return parc, depot, nil
}

func situationDe(a dbclients.AgentEtCibles, parc, depot string) miseajour.Situation {
	return miseajour.Situation{
		Declaree: a.Declaree,
		Attendue: parcversion.Resoudre(parcversion.Cibles{
			Derogation: a.Derogation, Groupes: a.Groupes, Parc: parc,
		}),
		CompteRendu: miseajour.CompteRendu{
			Version: a.CompteRendu.Version, Resultat: a.CompteRendu.Resultat, Motif: a.CompteRendu.Motif,
		},
		Depot:                  depot,
		RetrogradationDemandee: a.DerogationRetrograder,
	}
}

// repondreALaDemande : 09_01 → 09_02 (ordre) ou 09_03 (rien à faire).
//
// Une base qui ne répond pas donne « rien à faire » : l'agent redemandera à sa
// prochaine connexion, et rien ne justifie de lui faire tenter quoi que ce soit
// sur une lecture qui n'a pas abouti.
func repondreALaDemande(t storage.Trames_struct_client) string {
	s, err := lireSituation(t.ClientSoftwareID)
	if err != nil {
		logs.Write_Log("WARNING", "miseajour: demande de "+t.ClientSoftwareID+" sans réponse : "+err.Error())
		return trame.ReponseClient("09_03", t.Destination_Server, t.SessionIntegritykey,
			"situation illisible côté core")
	}
	d := miseajour.Decider(s)
	if d.Ordre == nil {
		logs.Write_Log("DEBUG", "miseajour: "+t.ClientSoftwareID+" — rien à faire : "+d.Motif)
		return trame.ReponseClient("09_03", t.Destination_Server, t.SessionIntegritykey, d.Motif)
	}
	niveau := "INFO"
	if d.Ordre.Retrograder {
		niveau = "SECURITY" // une rétrogradation, même demandée, se voit
	}
	logs.Write_Log(niveau, fmt.Sprintf("miseajour: ordre %s (dépôt %s, rétrogradation : %v) remis à %s, qui déclare %q",
		d.Ordre.Version, d.Ordre.Depot, d.Ordre.Retrograder, t.ClientSoftwareID, s.Declaree))
	noterLEnvoi(t.ClientSoftwareID, d.Ordre.Version)
	return trame.ReponseClient("09_02", t.Destination_Server, t.SessionIntegritykey, d.Ordre.Contenu()...)
}

// enregistrerCompteRendu : remplaçable par les tests.
var enregistrerCompteRendu = func(computeurID string, c miseajour.CompteRendu) error {
	return dbclients.EnregistrerCompteRendu(database.GetDatabase(), computeurID, c.Version, c.Resultat, c.Motif)
}

// recevoirLeCompteRendu : 09_04 → 09_05.
//
// L'accusé part même si l'écriture échoue : l'agent n'a rien à refaire, et lui
// faire renvoyer son compte rendu ne réparerait pas la base.
func recevoirLeCompteRendu(t storage.Trames_struct_client) string {
	c, err := miseajour.LireCompteRendu(t.Content)
	if err != nil {
		logs.Write_Log("WARNING", "miseajour: compte rendu illisible de "+t.ClientSoftwareID+" : "+err.Error())
		return ""
	}
	if err := enregistrerCompteRendu(t.ClientSoftwareID, c); err != nil {
		logs.Write_Log("ERROR", "miseajour: compte rendu de "+t.ClientSoftwareID+" non enregistré : "+err.Error())
	}
	niveau := "INFO"
	switch {
	case c.Resultat == miseajour.ResultatEchec:
		// Une machine revenue en arrière : elle tourne, mais pas avec ce qu'on
		// lui a demandé, et elle ne retentera pas seule.
		niveau = "WARNING"
	case c.Resultat == miseajour.ResultatRefuse && strings.Contains(c.Motif, "rétrograd"):
		niveau = "SECURITY"
	case c.Resultat == miseajour.ResultatRefuse:
		niveau = "WARNING"
	}
	logs.Write_Log(niveau, fmt.Sprintf("miseajour: %s rend compte de %s : %s%s",
		t.ClientSoftwareID, c.Version, c.Resultat, motifEntre(c.Motif)))
	oublierLEnvoi(t.ClientSoftwareID)
	return trame.ReponseClient("09_05", t.Destination_Server, t.SessionIntegritykey)
}

// enregistrerConfiguration : remplaçable par les tests.
var enregistrerConfiguration = func(computeurID string, c miseajour.CompteRenduConf) error {
	return dbclients.EnregistrerConfiguration(database.GetDatabase(), computeurID, c.Etat, c.Motif)
}

// recevoirLaConfiguration : 09_07 → 09_08 (TO-DO 117).
//
// Un écart est un WARNING : la machine tourne, mais sa configuration n'est
// pas celle de sa version — et c'est souvent sur un chemin d'authentification
// (sshd_config, une pile PAM).
func recevoirLaConfiguration(t storage.Trames_struct_client) string {
	c, err := miseajour.LireCompteRenduConf(t.Content)
	if err != nil {
		logs.Write_Log("WARNING", "confsys: compte rendu illisible de "+t.ClientSoftwareID+" : "+err.Error())
		return ""
	}
	if err := enregistrerConfiguration(t.ClientSoftwareID, c); err != nil {
		logs.Write_Log("ERROR", "confsys: compte rendu de "+t.ClientSoftwareID+" non enregistré : "+err.Error())
	}
	niveau := "INFO"
	switch c.Etat {
	case miseajour.ConfEcart:
		niveau = "WARNING"
	case miseajour.ConfConforme:
		niveau = "DEBUG"
	}
	logs.Write_Log(niveau, fmt.Sprintf("confsys: configuration système de %s : %s%s",
		t.ClientSoftwareID, c.Etat, motifEntre(c.Motif)))
	return trame.ReponseClient("09_08", t.Destination_Server, t.SessionIntegritykey)
}

// Remplaçables par les tests.
var (
	jeuApres = func(n int) (paquetagent.JeuStocke, bool, error) {
		return keymanagement.MagasinPaquets{}.JeuApres(n)
	}
	enregistrerJeuAgent = func(computeurID string, n int) error {
		return dbclients.EnregistrerJeuAgent(database.GetDatabase(), computeurID, n)
	}
)

// JeuAJour : le contenu de la 09_10 quand il n'y a rien de plus haut.
const JeuAJour = "a_jour"

// servirLeJeuDeCles : 09_09 → 09_10 (TO-DO 207).
//
// La demande dit le numéro que la machine tient ; il est rangé (c'est ce que
// « --pkg-key rotate-status » compte avant de basculer). La réponse est le
// PLUS PETIT jeu au-dessus — signé par une clé que la machine tient, puisque
// chaque jeu l'est par l'active du jeu précédent —, ou « a_jour ». L'agent
// vérifie, applique, et redemande : il remonte la chaîne seul.
func servirLeJeuDeCles(t storage.Trames_struct_client) string {
	n, err := strconv.Atoi(strings.TrimSpace(t.Content))
	if err != nil || n < 0 {
		logs.Write_Log("WARNING", "clespaquets: demande illisible de "+t.ClientSoftwareID+" : "+t.Content)
		return ""
	}
	if err := enregistrerJeuAgent(t.ClientSoftwareID, n); err != nil {
		logs.Write_Log("ERROR", "clespaquets: jeu de "+t.ClientSoftwareID+" non enregistré : "+err.Error())
	}
	j, ok, err := jeuApres(n)
	if err != nil {
		logs.Write_Log("WARNING", "clespaquets: jeux illisibles pour "+t.ClientSoftwareID+" : "+err.Error())
		return trame.ReponseClient("09_10", t.Destination_Server, t.SessionIntegritykey, JeuAJour)
	}
	if !ok {
		return trame.ReponseClient("09_10", t.Destination_Server, t.SessionIntegritykey, JeuAJour)
	}
	logs.Write_Log("INFO", fmt.Sprintf("clespaquets: jeu n°%d remis à %s, qui tient le n°%d", j.Numero, t.ClientSoftwareID, n))
	return trame.ReponseClient("09_10", t.Destination_Server, t.SessionIntegritykey,
		strconv.Itoa(j.Numero), base64.StdEncoding.EncodeToString([]byte(j.Corps)),
		base64.StdEncoding.EncodeToString([]byte(j.Enveloppe)))
}

func motifEntre(m string) string {
	if strings.TrimSpace(m) == "" {
		return ""
	}
	return " (" + m + ")"
}
