package display

import (
	"fmt"
	"strings"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// DisplayClusterNode affiche la fiche d'un nœud — `cluster show` (TO-DO 148).
//
// La liste porte douze colonnes et n'en tient plus une de détail. La fiche dit
// tout d'un nœud, et surtout ce que la liste résume : le détail des sessions
// d'un core, et l'ÂGE de la mesure. Un compteur sans son âge se lit comme
// l'état courant, et c'est la question qu'on se pose avant de purger un nœud
// (TO-DO 147) : « est-il vraiment vide, ou ne dit-il plus rien ? ».
func DisplayClusterNode(n clusterstorage.Node, maintenant time.Time) string {
	f := NouvelleFiche("Nœud " + n.Hostname)
	f.Ajouter("Rôle", n.Role)
	f.Ajouter("État", n.Status)
	f.Ajouter("Dernier battement", n.LastHeartbeat.Format("2006-01-02 15:04:05"))
	f.Ajouter("Version", n.VersionCode)
	if n.VersionSDK != "" {
		f.Ajouter("SDK", n.VersionSDK)
	}

	f.AjouterSection("Accès")
	acces := clusterstorage.AdresseAffichee(n.AdresseEffective(), n.PortEffectif())
	if n.ExpositionDeclaree() {
		acces += " (déclarée)"
		f.Ajouter("Vu par le nœud", clusterstorage.AdresseAffichee(n.IPAddress, n.Port))
	}
	f.Ajouter("Accès des agents", acces)
	f.Ajouter("Rotation", rotationLisible(n.ExposeAuxAgents))
	if n.Priorite != 0 {
		f.Ajouter("Priorité", fmt.Sprint(n.Priorite))
	}
	if len(n.GroupesAffins) > 0 {
		f.Ajouter("Sert en priorité", strings.Join(n.GroupesAffins, ", "))
	}

	if m := n.Maintenance; m != nil && (m.Active || !m.PurgeDemandee.IsZero()) {
		f.AjouterSection("Maintenance")
		if m.Active {
			f.Ajouter("État", fmt.Sprintf("en maintenance depuis le %s, par %s — servi à personne",
				m.Depuis.Format("2006-01-02 15:04:05"), m.Par))
		} else {
			f.Ajouter("État", "en service")
		}
		switch {
		case m.PurgeEnCours():
			f.Ajouter("Purge", fmt.Sprintf("demandée le %s par %s — en cours (le core la lance à son battement)",
				m.PurgeDemandee.Format("2006-01-02 15:04:05"), m.PurgePar))
		case m.PurgeFaite():
			f.Ajouter("Purge", fmt.Sprintf("terminée le %s : %d session(s) fermée(s) par la purge",
				m.PurgeTerminee.Format("2006-01-02 15:04:05"), m.Fermees))
		}
	}

	f.AjouterSection("Sessions")
	switch {
	case n.Sessions != nil:
		s := n.Sessions
		f.Ajouter("Machines", fmt.Sprintf("%d (tunnels ouverts : %d)", s.Machines, s.Tunnels))
		f.Ajouter("Comptes", fmt.Sprintf("%d session(s) de compte de l'annuaire", s.Comptes))
		f.Ajouter("Poignées de main", fmt.Sprint(s.Poignees))
		f.Ajouter("Mesure", fmt.Sprintf("%s (il y a %s)",
			s.Mesure.Format("15:04:05"), ageLisible(maintenant.Sub(s.Mesure))))
	case strings.EqualFold(n.Role, "core"):
		// Un core sans mesure : arrêté, d'une version antérieure, ou dont la
		// dernière mesure est trop ancienne. Le dire plutôt qu'afficher zéro.
		f.Ajouter("Mesure", "aucune récente — core arrêté, ou antérieur à la publication des sessions")
	default:
		f.Ajouter("Mesure", "sans objet : seul un core publie ses sessions")
	}

	if n.Relais != nil {
		f.AjouterSection("Relais")
		f.Ajouter("Connexions", relaisLisible(n.Relais))
		f.Ajouter("Trafic", traficLisible(n.Relais))
		f.Ajouter("Détail", "vlt cluster relais "+n.Hostname)
	}

	return f.String() + "\n" +
		"Ces mesures sont publiées par le nœud lui-même : elles s'affichent, elles\n" +
		"n'ordonnent pas la liste servie aux agents. Les sessions SSH ouvertes sur les\n" +
		"postes passent dans le tunnel de leur machine : elles ne sont pas des\n" +
		"« sessions de compte ».\n"
}

// ageLisible rend une durée courte à la seconde, longue à la minute.
func ageLisible(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < 2*time.Minute {
		return fmt.Sprintf("%d s", int(d.Seconds()))
	}
	return fmt.Sprintf("%d min", int(d.Minutes()))
}
