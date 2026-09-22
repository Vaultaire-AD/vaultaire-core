// Package debugreport écrit, à intervalle régulier, un rapport complet de
// l'état de l'agent dans un journal dédié : /var/log/vaultaire/vlt_client-Debug.log.
//
// # À quoi il sert
//
// Diagnostiquer un poste sans y passer une heure : à quel nœud il est connecté
// et depuis quand, dans quel ordre il essaierait les autres, quelles sessions
// Ducky il tient, qui est connecté sur la machine, où en sont ses GPO. Tout ce
// qui, jusqu'ici, se reconstituait en recoupant plusieurs journaux — ou ne se
// reconstituait pas, faute d'être retenu nulle part.
//
// # Activation
//
// Désactivé par défaut. Deux façons de l'activer, la ligne de commande primant :
//
//	client_conf.json   "debug": {"enabled": true, "interval_seconds": 60}
//	ligne de commande  vaultaire_client -debug [-debug-interval 30]
//
// # Ce qu'il ne fait PAS
//
//   - Il ne lance aucun contrôle coûteux : pas de scan de conformité GPO (qui
//     interroge services et pare-feu), pas d'appel réseau. Il lit l'état que
//     l'agent tient déjà en mémoire et sur disque.
//   - Il n'écrit aucun secret : ni clé de session (seulement sa présence), ni
//     mot de passe, ni contenu de clé privée.
package debugreport

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Famille est le nom du journal (sans « .log »), sous le répertoire des
// journaux de l'agent.
const Famille = "vlt_client-Debug"

// IntervalleMin borne la période : un rapport par seconde ferait tourner le
// journal en quelques heures sans rien apprendre de plus.
const IntervalleMin = 5 * time.Second

var demarre atomic.Bool

// ecrire est une variable pour les tests.
var ecrire = func(rapport string) { logs.WriteLog(Famille, rapport) }

// Demarrer lance la boucle, une seule fois par processus.
func Demarrer(intervalle time.Duration) {
	if !demarre.CompareAndSwap(false, true) {
		return
	}
	if intervalle < IntervalleMin {
		intervalle = IntervalleMin
	}
	logs.Write_log("INFO", fmt.Sprintf(
		"debug : rapport d'état toutes les %s dans %s.log", intervalle, Famille))
	logs.Go("rapport de debug", func() {
		debut := time.Now()
		for {
			ecrire(Construire(Collecter(debut, intervalle)))
			time.Sleep(intervalle)
		}
	})
}

// --- mise en forme -----------------------------------------------------------

const largeur = 78

func centrer(s string) string {
	n := len([]rune(s))
	if n >= largeur {
		return s
	}
	return strings.Repeat(" ", (largeur-n)/2) + s
}

// Construire met un état en forme.
func Construire(e Etat) string {
	var b strings.Builder
	barre := strings.Repeat("=", largeur)
	b.WriteString("\n" + barre + "\n")
	b.WriteString(centrer("Rapport de debug") + "\n")
	b.WriteString(centrer(e.Instant.Format("02/01/2006 - 15h04")) + "\n")
	b.WriteString(barre + "\n")

	section(&b, "Agent")
	cle(&b, "Machine", e.Agent.ComputeurID)
	cle(&b, "Nom d'hôte", e.Agent.Hostname)
	cle(&b, "Type", e.Agent.Type)
	cle(&b, "Nœud serveur", ouiNon(e.Agent.Serveur))
	cle(&b, "Version agent", e.Agent.Version)
	cle(&b, "Version SDK", e.Agent.VersionSDK)
	cle(&b, "PID", fmt.Sprint(e.Agent.PID))
	cle(&b, "Actif depuis", duree(e.Agent.Uptime))
	cle(&b, "Configuration", e.Agent.Config)
	cle(&b, "Clés", e.Agent.Cles)
	cle(&b, "Journaux", e.Agent.Journaux)
	cle(&b, "Journal DEBUG", ouiNon(e.Agent.DebugJournal))
	cle(&b, "Rapport", "toutes les "+e.Agent.Intervalle.String())

	section(&b, "Connexion au cluster")
	c := e.Connexion
	cle(&b, "Tunnel supervisé", ouiNon(c.Supervise))
	if c.Adresse == "" {
		cle(&b, "Nœud joint", "AUCUN — tunnel non établi")
	} else {
		cle(&b, "Nœud joint", c.Adresse+nomRole(c.Hostname, c.Role))
		cle(&b, "Depuis", date(c.Depuis)+" ("+duree(e.Instant.Sub(c.Depuis))+")")
	}
	cle(&b, "Tunnel machine", c.EtatTunnel)
	cle(&b, "Connexions établies", fmt.Sprint(c.Etablissements))
	if c.DernierEchec != "" {
		cle(&b, "Dernier échec", date(c.DernierEchecA)+" — "+c.DernierEchec)
	}
	cle(&b, "Clé du core en place", c.EmpreinteCle)
	cle(&b, "Empreintes de confiance", fmt.Sprintf("%d (%s)", c.NbEmpreintes, c.FichierEmpreintes))

	section(&b, "Nœuds dans l'ordre d'essai")
	if e.DerniereListe.IsZero() {
		b.WriteString("  Dernière liste 04_04 : jamais reçue depuis le démarrage\n")
	} else {
		b.WriteString("  Dernière liste 04_04 : " + date(e.DerniereListe) + "\n")
	}
	if len(e.Noeuds) == 0 {
		b.WriteString("  (aucun nœud connu — ni appris, ni dans le fichier)\n")
	}
	for i, n := range e.Noeuds {
		marque := "  "
		if n.Courant {
			marque = "▶ "
		}
		fmt.Fprintf(&b, "  %s%2d. %-22s %-7s %-20s %s\n", marque, i+1, n.Adresse, vide(n.Role), vide(n.Hostname), n.Source)
	}

	section(&b, fmt.Sprintf("Sessions Ducky (%d)", len(e.Sessions)))
	if len(e.Sessions) == 0 {
		b.WriteString("  aucune\n")
	}
	for _, s := range e.Sessions {
		fmt.Fprintf(&b, "  - %-10s %-14s %-13s %s → %s\n", court(s.SessionID), s.Username, s.Statut, vide(s.Local), vide(s.Distant))
		fmt.Fprintf(&b, "      ouverte %s, dernière activité il y a %s, sûre=%s, clé=%s\n",
			date(s.Creee), duree(e.Instant.Sub(s.Vue)), ouiNon(s.Sure), ouiNon(s.Cle))
	}
	if e.SessionsUtilisateurDucky > 0 {
		fmt.Fprintf(&b, "  ⚠ %d session(s) Ducky au nom d'un utilisateur : les authentifications PAM passent\n"+
			"    normalement par le tunnel machine, sans session propre.\n", e.SessionsUtilisateurDucky)
	}

	section(&b, fmt.Sprintf("Sessions ouvertes sur la machine (%d)", len(e.SessionsLocales)))
	if e.ErreurSessions != "" {
		b.WriteString("  illisibles : " + e.ErreurSessions + "\n")
	} else if len(e.SessionsLocales) == 0 {
		b.WriteString("  aucune\n")
	}
	for _, s := range e.SessionsLocales {
		genre := "local"
		if s.Vaultaire {
			genre = "Vaultaire"
		}
		fmt.Fprintf(&b, "  - %-30s %-9s %-8s depuis %s %s\n", s.Utilisateur, genre, s.Terminal, s.Depuis, s.Origine)
	}

	section(&b, fmt.Sprintf("Comptes Vaultaire provisionnés (%d)", len(e.Comptes)))
	if e.ErreurComptes != "" {
		b.WriteString("  illisibles : " + e.ErreurComptes + "\n")
	} else if len(e.Comptes) == 0 {
		b.WriteString("  aucun\n")
	}
	for _, c := range e.Comptes {
		etat := ""
		if c.Connecte {
			etat = "connecté"
		}
		fmt.Fprintf(&b, "  - %-34s uid=%-6d %s\n", c.Nom, c.UID, etat)
	}

	section(&b, "Canal PAM")
	cle(&b, "Demandes en attente", fmt.Sprint(e.PAM.EnAttente))
	cle(&b, "Connexions refusées", fmt.Sprintf("%d (appelant non root)", e.PAM.Refusees))

	section(&b, "GPO")
	if e.GPO.Machine == nil {
		b.WriteString("  Machine : aucune politique appliquée\n")
	} else {
		ecrireScope(&b, "Machine", *e.GPO.Machine)
	}
	for _, u := range e.GPO.Utilisateurs {
		ecrireScope(&b, "Utilisateur "+u.Nom, u)
	}
	if len(e.GPO.Cycles) == 0 {
		b.WriteString("  Aucun cycle depuis le démarrage\n")
	}
	for _, c := range e.GPO.Cycles {
		qui := c.Scope
		if c.Username != "" {
			qui += " " + c.Username
		}
		ligne := fmt.Sprintf("  Dernier cycle %-24s %s (%s) — %s", qui, date(c.Debut), c.Duree.Round(time.Millisecond), c.Resume)
		if c.Motif != "" {
			ligne += " — " + c.Motif
		}
		b.WriteString(ligne + "\n")
		for _, m := range c.Echecs {
			b.WriteString("      ✗ " + m + "\n")
		}
	}

	section(&b, "Révocations appliquées")
	if len(e.Revocations) == 0 {
		b.WriteString("  aucune\n")
	}
	for _, r := range e.Revocations {
		b.WriteString("  - " + r + "\n")
	}

	section(&b, "Groupes du domaine")
	cle(&b, "Groupes créés sur la machine", fmt.Sprint(e.Groupes.Crees))
	cle(&b, "Synchronisation", "toutes les "+e.Groupes.Cadence.String())

	if len(e.Alertes) > 0 {
		section(&b, "⚠ Points d'attention")
		for _, a := range e.Alertes {
			b.WriteString("  - " + a + "\n")
		}
	}
	b.WriteString(barre + "\n")
	return b.String()
}

func ecrireScope(b *strings.Builder, titre string, s ScopeGPO) {
	fmt.Fprintf(b, "  %s : empreinte %s, version %d, appliquée %s, statut %s, %d module(s)\n",
		titre, s.Empreinte, s.Version, vide(s.AppliqueeLe), vide(s.Statut), s.Modules)
	if s.Audit > 0 {
		fmt.Fprintf(b, "      dont %d en mode audit (écart signalé, jamais corrigé)\n", s.Audit)
	}
	fmt.Fprintf(b, "      %d fichier(s) suivi(s), %d contrôle(s) d'état\n", s.Fichiers, s.Controles)
}

func section(b *strings.Builder, titre string) {
	b.WriteString("\n── " + titre + " " + strings.Repeat("─", max(0, largeur-4-len([]rune(titre)))) + "\n")
}

func cle(b *strings.Builder, k, v string) { fmt.Fprintf(b, "  %-26s %s\n", k+" :", vide(v)) }

func vide(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func ouiNon(v bool) string {
	if v {
		return "oui"
	}
	return "non"
}

func nomRole(h, r string) string {
	switch {
	case h != "" && r != "":
		return " (" + h + ", " + r + ")"
	case h != "":
		return " (" + h + ")"
	case r != "":
		return " (" + r + ")"
	}
	return " (nœud du fichier de configuration)"
}

func court(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func date(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("02/01/2006 15:04:05")
}

func duree(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	j := d / (24 * time.Hour)
	d -= j * 24 * time.Hour
	if j > 0 {
		return fmt.Sprintf("%dj %s", j, d)
	}
	return d.String()
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
