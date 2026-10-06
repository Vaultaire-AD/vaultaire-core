package display

import (
	"fmt"
	"strings"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// DisplayRelais affiche les relais d'un proxy : ce qu'il expose, vers quoi, et
// où en est ce que le core lui demande (TO-DO 141).
//
// # Deux tables quand elles diffèrent, une seule sinon
//
// Quand le proxy applique ce que le core demande — ou que le core ne demande
// rien —, il n'y a qu'un état à montrer. Entre une écriture et son
// application, ou après un refus, il y en a deux : ce qu'on a DEMANDÉ et ce
// qui TOURNE. Les fondre ferait lire comme ouvert un port qui ne l'est pas, ou
// comme fermé un relais que le proxy tient toujours.
func DisplayRelais(noeud string, enLigne bool, v clusterstorage.VueRelais) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Relais de %s\n\n", noeud)

	fmt.Fprintf(&b, "  %s\n", v.Resume())
	if v.Pilote && v.ModifiePar != "" {
		fmt.Fprintf(&b, "  Dernière modification : %s, le %s\n", v.ModifiePar, v.ModifieLe.Local().Format("2006-01-02 15:04:05"))
	}
	if v.Connu {
		age := "à " + v.Recu.Local().Format("15:04:05")
		if !v.Frais {
			// Un état périmé affiché sans son âge se lit comme l'état courant.
			age = "le " + v.Recu.Local().Format("2006-01-02 15:04:05") + " — PÉRIMÉ, le proxy ne rend plus compte"
		}
		fmt.Fprintf(&b, "  Dernier compte rendu du proxy : %s\n", age)
		if !v.PilotageAccepte {
			b.WriteString("  Ce proxy GARDE LA MAIN sur ses relais (pilotage_par_le_core: false dans son fichier).\n")
		}
	}
	if !enLigne {
		b.WriteString("  Le proxy est HORS LIGNE : ce qui suit est son dernier état connu.\n")
	}
	b.WriteString("\n")

	if len(v.Relais) == 0 && len(v.EnService) == 0 {
		b.WriteString("Aucun relais connu.\n")
		return b.String()
	}

	if len(v.Relais) > 0 {
		if v.Pilote {
			b.WriteString("Demandés par le core\n\n")
		}
		b.WriteString(tableDeRelais(v.Relais))
	}
	if len(v.EnService) > 0 {
		b.WriteString("\nEn service sur le proxy en ce moment\n\n")
		b.WriteString(tableDeRelais(v.EnService))
	}

	b.WriteString("\n  ÉTAT « demandé » : le core le veut, le proxy n'a pas encore dit ce qu'il en est.\n" +
		"  « appliqué » : le proxy l'a ouvert. « refusé » : il ne peut pas, le motif est sous la ligne.\n" +
		"  « du fichier » : le core ne pilote pas ce proxy, le relais vient de son fichier.\n" +
		"  CIBLES : vers quoi une connexion partirait maintenant, d'après le proxy.\n" +
		"  ACT./TOTAL : connexions en cours / depuis le démarrage du proxy ; ✗ celles qui ne sont pas passées.\n")
	return b.String()
}

func tableDeRelais(liste []clusterstorage.RelaisVue) string {
	tb := NouvelleTable("ÉTAT", "RELAIS", "TYPE", "ÉCOUTE", "SOURCE DES CIBLES", "CIBLES", "ACT./TOTAL", "TRAFIC")
	var notes []string
	for _, r := range liste {
		ecoute := r.Ecoute
		if r.EcouteEffective != "" && r.EcouteEffective != r.Ecoute {
			ecoute = r.EcouteEffective
		}
		compteurs, trafic := "", ""
		if m := r.Mesure; m != nil {
			compteurs = fmt.Sprintf("%d/%d", m.Actives, m.Total)
			if e := m.Ecartees(); e > 0 {
				compteurs += fmt.Sprintf(" ✗%d", e)
			}
			trafic = m.TraficLisible()
		}
		tb.Ajouter(
			Valeur(r.LibelleEtat()),
			Valeur(r.Nom),
			Valeur(r.Type),
			Valeur(ecoute),
			Valeur(r.SourceLisible()),
			Valeur(r.CiblesLisibles()),
			Valeur(compteurs),
			Valeur(trafic),
		)
		if r.Motif != "" {
			notes = append(notes, fmt.Sprintf("  %s : %s", r.Nom, r.Motif))
		}
		notes = append(notes, fmt.Sprintf("  %s — %s", r.Nom, r.Limites()))
	}
	return tb.String() + strings.Join(notes, "\n") + "\n"
}
