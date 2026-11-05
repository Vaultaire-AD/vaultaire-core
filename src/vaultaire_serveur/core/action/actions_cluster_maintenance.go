package action

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	clusterdatabase "vaultaire/cluster/cluster_database"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/reglages"
)

// Oublier, mettre en maintenance, purger un nœud — TO-DO 146 et 147.
//
// # La clé : write:cluster, pour les trois
//
// Ce sont des décisions sur la topologie du parc, comme l'exposition et
// l'affinité. Aucune ne touche à un domaine : portée globale.
//
// La PURGE fait reconnecter tous les postes d'un core. On aurait pu lui
// donner une clé à elle ; elle ne s'applique qu'à un core DÉJÀ en maintenance,
// geste qui exige write:cluster, et la séparer donnerait deux droits à
// accorder pour un même geste d'exploitation.

// EnregistrerActionsMaintenanceCluster ajoute l'oubli, la maintenance et la purge.
func EnregistrerActionsMaintenanceCluster(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "cluster.forget",
		CleRBAC:  permission.ActionWriteCluster,
		Portee:   PorteeGlobale,
		Resume:   "oublie un nœud hors ligne sans attendre le délai de purge",
		Executer: oublierNoeud,
	})
	r.MustEnregistrer(Definition{
		Nom:      "cluster.set_maintenance",
		CleRBAC:  permission.ActionWriteCluster,
		Portee:   PorteeGlobale,
		Resume:   "met un nœud en maintenance (hors de toutes les listes), ou l'en sort",
		Executer: reglerMaintenance,
	})
	r.MustEnregistrer(Definition{
		Nom:      "cluster.purge",
		CleRBAC:  permission.ActionWriteCluster,
		Portee:   PorteeGlobale,
		Resume:   "vide un core en maintenance de ses sessions",
		Executer: purgerNoeud,
	})
}

// silenceAvantOubli : depuis combien de temps un nœud doit se taire.
//
// La fraîcheur des mesures, c'est-à-dire trois battements, trois minutes au
// moins : un nœud plus silencieux que cela ne publie plus rien, un nœud qui
// l'est moins peut être en train de redémarrer.
var silenceAvantOubli = func() time.Duration {
	return clusterdatabase.FraicheurPour(reglages.Duree(reglages.CleBattementCluster))
}

// Remplaçables par les tests : la décision s'éprouve sans base.
var (
	oublierEnBase = func(h string, s time.Duration) (clusterdatabase.BilanOubli, error) {
		return clusterdatabase.OublierNoeud(database.GetDatabase(), h, s)
	}
	poserMaintenanceEnBase = func(h string, on bool, par string) error {
		return clusterdatabase.PoserMaintenance(database.GetDatabase(), h, on, par)
	}
	coresDisponiblesHors = func(h string) (int, error) {
		return clusterdatabase.CoresDisponiblesHors(database.GetDatabase(), h)
	}
	roleDuNoeud = func(h string) (string, error) {
		n, err := clusterdatabase.NoeudParHostname(database.GetDatabase(), h)
		if err != nil {
			return "", err
		}
		return n.Role, nil
	}
	demanderPurgeEnBase = func(h, par string, etalement int) error {
		return clusterdatabase.DemanderPurge(database.GetDatabase(), h, par, etalement)
	}
)

func nomDuNoeud(p Params) (string, error) {
	h := strings.TrimSpace(p.Get("node"))
	if h == "" {
		return "", fmt.Errorf("nom du nœud requis")
	}
	return h, nil
}

// --- oubli (146) ------------------------------------------------------------------

func oublierNoeud(a Appelant, p Params) (Resultat, error) {
	hostname, err := nomDuNoeud(p)
	if err != nil {
		return Resultat{}, err
	}
	b, err := oublierEnBase(hostname, silenceAvantOubli())
	if errors.Is(err, clusterdatabase.ErrNoeudInconnu) {
		return Resultat{}, fmt.Errorf("aucun nœud « %s » dans le cluster", hostname)
	}
	if err != nil {
		return Resultat{}, err
	}

	perdu := ceQuiPartAvec(b)
	// SECURITY : retirer un nœud de la carte est un geste sur l'infrastructure,
	// et ce qui part avec lui n'est écrit nulle part ailleurs.
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"cluster: nœud %s (%s) OUBLIÉ par %s — dernier battement %s ; parti avec lui : %s",
		b.Hostname, b.Role, a.Username, b.DernierBattement.Format("2006-01-02 15:04:05"), perdu))

	return Resultat{
		Message: fmt.Sprintf("Nœud %s (%s) oublié — dernier battement le %s.\n"+
			"Parti avec lui : %s.\n"+
			"S'il revient, il se réinscrira seul : ces réglages seront à refaire.",
			b.Hostname, b.Role, b.DernierBattement.Format("2006-01-02 15:04:05"), perdu),
		Donnees: b,
	}, nil
}

// ceQuiPartAvec énumère les décisions d'exploitation perdues avec la ligne.
func ceQuiPartAvec(b clusterdatabase.BilanOubli) string {
	var l []string
	if b.AdresseDeclaree != "" || b.PortPublic != 0 {
		l = append(l, fmt.Sprintf("l'adresse déclarée %s", strings.TrimSpace(
			b.AdresseDeclaree+portSiNonNul(b.PortPublic))))
	}
	if b.Priorite != 0 {
		l = append(l, fmt.Sprintf("la priorité %d", b.Priorite))
	}
	if b.HorsRotation {
		l = append(l, "le retrait de la rotation")
	}
	if b.Maintenance {
		l = append(l, "la maintenance")
	}
	if len(b.Groupes) > 0 {
		l = append(l, "l'affinité "+strings.Join(b.Groupes, ", "))
	}
	if len(b.Relais) > 0 {
		l = append(l, "les relais demandés "+strings.Join(b.Relais, ", "))
	}
	if len(l) == 0 {
		return "aucun réglage"
	}
	return strings.Join(l, " ; ")
}

func portSiNonNul(p int) string {
	if p == 0 {
		return ""
	}
	return ":" + strconv.Itoa(p)
}

// --- maintenance (147) --------------------------------------------------------------

func reglerMaintenance(a Appelant, p Params) (Resultat, error) {
	hostname, err := nomDuNoeud(p)
	if err != nil {
		return Resultat{}, err
	}
	var active bool
	switch strings.ToLower(p.Get("mode")) {
	case "on", "oui", "true", "1":
		active = true
	case "off", "non", "false", "0":
		active = false
	default:
		return Resultat{}, fmt.Errorf("mode requis : on ou off (reçu %q)", p.Get("mode"))
	}

	role, err := roleDuNoeud(hostname)
	if err != nil {
		return Resultat{}, fmt.Errorf("aucun nœud « %s » dans le cluster", hostname)
	}

	// LE GARDE-FOU : le dernier core servi. Le mettre en maintenance retire
	// des listes le seul serveur d'authentification du parc — c'est la
	// commande qui coupe tout. Pas un refus : un cluster à un seul core a le
	// droit d'assumer une fenêtre de maintenance, mais il le dit en le tapant.
	if active && role == "core" {
		restants, err := coresDisponiblesHors(hostname)
		if err != nil {
			return Resultat{}, fmt.Errorf("impossible de compter les autres cores : %w", err)
		}
		if restants == 0 && !confirme(p) {
			return Resultat{}, &ErrConfirmationRequise{
				Motif: fmt.Sprintf(
					"%s est le DERNIER core servi aux agents : RIEN n'a été changé.\n"+
						"En maintenance, plus aucun core ne figurerait dans la liste du parc. Les "+
						"tunnels ouverts tiendraient, mais un poste qui redemande sa liste n'aurait "+
						"plus que son fichier de configuration pour se reconnecter.\n"+
						"Pour l'assumer : « cluster maintenance %s on --confirm », ou le bouton "+
						"Confirmer de la page Cluster.", hostname, hostname),
				Rejouer: Params{"node": hostname, "mode": "on", "confirm": "yes"},
			}
		}
	}

	if err := poserMaintenanceEnBase(hostname, active, a.Username); err != nil {
		if errors.Is(err, clusterdatabase.ErrNoeudInconnu) {
			return Resultat{}, fmt.Errorf("aucun nœud « %s » dans le cluster", hostname)
		}
		return Resultat{}, err
	}

	if !active {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"cluster: maintenance de %s LEVÉE par %s — de nouveau dans les listes", hostname, a.Username))
		return Resultat{Message: fmt.Sprintf(
			"%s sort de maintenance : il revient dans les listes au prochain tour de chaque "+
				"agent (ou à « cluster refresh »), tel qu'il était — rotation et priorité "+
				"n'ont pas été touchées.", hostname)}, nil
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"cluster: %s (%s) mis en MAINTENANCE par %s — retiré de toutes les listes", hostname, role, a.Username))
	suite := ""
	if role == "core" {
		suite = fmt.Sprintf("\nLes sessions déjà ouvertes y restent. Pour les déplacer : "+
			"« cluster purge %s » ; suivi : « cluster show %s ».", hostname, hostname)
	}
	return Resultat{Message: fmt.Sprintf(
		"%s en maintenance : retiré de la liste des agents, de celle des proxies et des "+
			"services (04_04, 04_16). Il reste dans le cluster et continue de battre.%s",
		hostname, suite)}, nil
}

// --- purge (147) --------------------------------------------------------------------

// etalementMax : au-delà d'une heure, la purge n'en est plus une — c'est une
// maintenance qu'on laisse se vider seule.
const etalementMax = 3600

func purgerNoeud(a Appelant, p Params) (Resultat, error) {
	hostname, err := nomDuNoeud(p)
	if err != nil {
		return Resultat{}, err
	}
	etalement := 0
	if brut := p.Get("spread"); brut != "" {
		etalement, err = strconv.Atoi(brut)
		if err != nil || etalement < 0 || etalement > etalementMax {
			return Resultat{}, fmt.Errorf("étalement invalide %q : un nombre de secondes entre 0 et %d",
				brut, etalementMax)
		}
	}

	err = demanderPurgeEnBase(hostname, a.Username, etalement)
	switch {
	case errors.Is(err, clusterdatabase.ErrNoeudInconnu):
		return Resultat{}, fmt.Errorf("aucun nœud « %s » dans le cluster", hostname)
	case errors.Is(err, clusterdatabase.ErrPurgeHorsMaintenance):
		return Resultat{}, fmt.Errorf("%s n'est pas en maintenance : purgé, il serait aussitôt "+
			"rejoint — il figure encore dans la liste des agents. D'abord « cluster maintenance %s on »",
			hostname, hostname)
	case errors.Is(err, clusterdatabase.ErrPurgePasUnCore):
		return Resultat{}, fmt.Errorf("%s n'est ni un core ni un proxy : seuls ceux-là portent des "+
			"sessions d'agents à fermer", hostname)
	case err != nil:
		return Resultat{}, err
	}

	affiche := "par défaut (60 s)"
	if etalement > 0 {
		affiche = fmt.Sprintf("sur %d s", etalement)
	}
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"cluster: PURGE de %s demandée par %s (étalement %s)", hostname, a.Username, affiche))
	if role, err := roleDuNoeud(hostname); err == nil && role == "proxy" {
		// TO-DO 176 : un proxy ne tient pas ses sessions, les cores les tiennent.
		return Resultat{Message: fmt.Sprintf(
			"Purge du proxy %s demandée. Chaque core la lance à son prochain battement (%s au plus), "+
				"sur les sessions qui lui arrivent par ce proxy :\n"+
				"  1. chaque machine relayée reçoit l'ordre de redemander sa liste — un agent à jour "+
				"quitte seul ce proxy, absent de la liste ;\n"+
				"  2. une minute après, le reste est fermé, étalé %s.\n"+
				"La session du proxy lui-même n'est pas fermée : il bat toujours.\n"+
				"Suivi : « cluster show %s » (sessions fermées, cumulées sur les cores).",
			hostname, reglages.Duree(reglages.CleBattementCluster), affiche, hostname)}, nil
	}
	return Resultat{Message: fmt.Sprintf(
		"Purge de %s demandée. Le core la lance à son prochain battement (%s au plus) :\n"+
			"  1. chaque machine reçoit l'ordre de redemander sa liste — un agent à jour quitte "+
			"seul ce core, absent de la liste ;\n"+
			"  2. une minute après, le reste est fermé, étalé %s.\n"+
			"Les sessions du portail web et de l'API ne sont pas touchées.\n"+
			"Suivi : « cluster show %s ».",
		hostname, reglages.Duree(reglages.CleBattementCluster), affiche, hostname)}, nil
}
