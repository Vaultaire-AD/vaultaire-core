package outil

import (
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"strings"

	"vaultaire/core/paquetagent"
)

// Les sous-commandes de la rotation de pkg_signing — TO-DO 207.
//
//	--pkg-key rotate-status                    où en est la rotation, et le parc
//	--pkg-key rotate-add    [--key <pem>]      geste 1 : clé suivante, jeu {active, suivante}
//	--pkg-key rotate-switch [--force]          geste 2 : la suivante signe désormais
//	--pkg-key rotate-retire [--key <pem>]      geste 3 : jeu {active}, l'ancienne oubliée
//	--pkg-key compromised   --confirm          clé compromise : remplacement HORS BANDE
//
// --key : la clé privée ACTIVE, en mode hors ligne (forget-private) — c'est
// elle qui signe le jeu. La logique est dans paquetagent (rotation.go).

func rotation(sous string, args []string, sortie, erreurs io.Writer, ouvrir func() (Cles, error)) int {
	echec := func(format string, a ...any) int {
		fmt.Fprintf(erreurs, "erreur : "+format+"\n", a...)
		return 1
	}
	force, confirme, fichierCle := false, false, ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--force" && sous == "rotate-switch":
			force = true
		case args[i] == "--confirm" && sous == "compromised":
			confirme = true
		case args[i] == "--key" && i+1 < len(args) && (sous == "rotate-add" || sous == "rotate-retire"):
			fichierCle = args[i+1]
			i++
		default:
			fmt.Fprint(erreurs, Aide)
			return 2
		}
	}
	if sous == "compromised" && !confirme {
		return echec("compromised remplace la clé de signature et TOUT le jeu de confiance : chaque " +
			"machine en service devra être réinstallée (« vlt create -c <id> -join ») pour accepter " +
			"de nouveau des paquets. Ajoutez --confirm")
	}
	cles, err := ouvrir()
	if err != nil {
		return echec("%v", err)
	}
	if cles.Magasin == nil {
		return echec("magasin des clés indisponible")
	}
	m := cles.Magasin
	horsLigne, err := lireCleHorsLigne(fichierCle)
	if err != nil {
		return echec("%v", err)
	}

	switch sous {
	case "rotate-status":
		e, err := paquetagent.LireEtat(m)
		if err != nil {
			return echec("%v", err)
		}
		fmt.Fprint(sortie, AfficherEtat(e))
		return 0
	case "rotate-add":
		j, err := paquetagent.Ajouter(m, horsLigne)
		if err != nil {
			return echec("%v", err)
		}
		fmt.Fprintf(sortie, "Jeu n°%d publié : l'active et la SUIVANTE. Les paquets restent signés par l'active.\n"+
			"Chaque agent le reçoit à sa prochaine connexion, au plus tard dans l'heure.\n"+
			"Suivre : --pkg-key rotate-status ; puis --pkg-key rotate-switch.\n", j.Numero)
		return 0
	case "rotate-switch":
		if err := paquetagent.Basculer(m, force); err != nil {
			return echec("%v", err)
		}
		fmt.Fprintln(sortie, "Bascule faite : la nouvelle clé signe désormais les paquets (--sign-package).\n"+
			"Re-signez les releases que le parc doit encore pouvoir installer, puis : --pkg-key rotate-retire.")
		return 0
	case "rotate-retire":
		j, err := paquetagent.Retirer(m, horsLigne)
		if err != nil {
			return echec("%v", err)
		}
		fmt.Fprintf(sortie, "Jeu n°%d publié : la seule clé active. L'ancienne est oubliée — rotation terminée.\n", j.Numero)
		return 0
	case "compromised":
		j, err := paquetagent.Compromise(m)
		if err != nil {
			return echec("%v", err)
		}
		e, _ := paquetagent.LireEtat(m)
		fmt.Fprintf(sortie, "Clé REMPLACÉE, jeu n°%d publié et signé par la nouvelle clé seule.\n\n"+
			"Les machines en service ne l'accepteront PAS par le réseau — c'est voulu : qui détient\n"+
			"l'ancienne clé pourrait signer un jeu aussi. Pour chacune (%d agent(s) Linux) :\n"+
			"  vlt create -c <computeur_id> -join <utilisateur>@<adresse>\n"+
			"qui redépose le fichier de clés. D'ici là, elles refusent tout paquet signé par la nouvelle clé.\n"+
			"Re-signez les releases à déployer : --sign-package <archive>.\n", j.Numero, e.Agents)
		return 0
	}
	fmt.Fprint(erreurs, Aide)
	return 2
}

func lireCleHorsLigne(chemin string) (*rsa.PrivateKey, error) {
	if chemin == "" {
		return nil, nil
	}
	contenu, err := os.ReadFile(chemin)
	if err != nil {
		return nil, fmt.Errorf("clé hors ligne : %w", err)
	}
	return paquetagent.LireClePrivee(contenu)
}

// AfficherEtat met l'état d'une rotation en forme.
func AfficherEtat(e paquetagent.EtatRotation) string {
	var b strings.Builder
	jeu := "aucun (clé de l'installation)"
	if e.Jeu > 0 {
		jeu = fmt.Sprintf("n°%d (%d clé(s))", e.Jeu, e.ClesDuJeu)
	}
	enLigne := "en base"
	if !e.ActiveEnLigne {
		enLigne = "hors ligne"
	}
	fmt.Fprintf(&b, "Rotation    : %s\nJeu publié  : %s\nActive      : %s (clé privée %s)\n", e.Phase, jeu, e.Active, enLigne)
	if e.Suivante != "" {
		fmt.Fprintf(&b, "Suivante    : %s\n", e.Suivante)
	}
	if e.Precedente != "" {
		fmt.Fprintf(&b, "Précédente  : %s\n", e.Precedente)
	}
	fmt.Fprintf(&b, "Agents      : %d sur %d tiennent le jeu publié\n", e.AJour, e.Agents)
	for i, a := range e.EnRetard {
		if i == 20 {
			fmt.Fprintf(&b, "  … et %d autre(s)\n", len(e.EnRetard)-20)
			break
		}
		fmt.Fprintf(&b, "  en retard : %s (%s) — jeu n°%d\n", a.Nom, a.ComputeurID, a.Numero)
	}
	switch e.Phase {
	case paquetagent.PhaseAjoutee:
		if len(e.EnRetard) == 0 {
			b.WriteString("\nLe parc a suivi : --pkg-key rotate-switch.\n")
		} else {
			b.WriteString("\nAttendre que le parc suive (une demande par connexion et par heure) avant rotate-switch.\n")
		}
	case paquetagent.PhaseBasculee:
		b.WriteString("\nRe-signer les releases utiles, puis --pkg-key rotate-retire.\n")
	}
	return b.String()
}
