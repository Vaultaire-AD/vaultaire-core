package hosthandler

import (
	"strconv"
	"strings"
	"testing"

	"vaultaire/core/reglages"
)

// Les lignes de nœud de 04_04 se lisent PAR POSITION, à la différence de 03_09
// et 05_02 qui se lisent par préfixe. C'est ce qui rend la ligne de cadence
// délicate ici, et ce que ces tests gardent.

// Le préfixe est déclaré des deux côtés du réseau et rien ne les lie à la
// compilation. Les faire diverger ferait rejeter la ligne comme un nœud
// malformé côté agent.
func TestLePrefixeResteCeluiDeLAgent(t *testing.T) {
	if PrefixeCadenceDecouverte != "disco:" {
		t.Errorf("PrefixeCadenceDecouverte = %q : la valeur doit rester identique à "+
			"celle de l'agent (decouverte.PrefixeCadence)", PrefixeCadenceDecouverte)
	}
}

// Le réglage est la SEULE source de la valeur envoyée : une constante restée
// dans le code aurait rendu le réglage muet, ce qui est le défaut corrigé.
func TestLaValeurEnvoyeeVientDuReglage(t *testing.T) {
	attendu := PrefixeCadenceDecouverte + strconv.Itoa(reglages.Valeur(reglages.CleListeDesNoeuds))
	if got := ligneCadenceDecouverte(); got != attendu {
		t.Fatalf("ligneCadenceDecouverte() = %q, attendu %q", got, attendu)
	}
}

// Une valeur aberrante ne doit pas partir : l'agent garde alors la sienne, ce
// qui vaut mieux que de lui faire appliquer un zéro — même s'il borne de son
// côté, une trame qui dit « zéro » est une trame fausse.
func TestUneValeurAberranteNeProduitAucuneLigne(t *testing.T) {
	ancienne := reglages.Valeur(reglages.CleListeDesNoeuds)
	if ancienne <= 0 {
		t.Skip("le réglage rend déjà une valeur non positive")
	}
	if ligneCadenceDecouverte() == "" {
		t.Fatal("aucune ligne produite pour une valeur pourtant valide")
	}
}

// La ligne ne doit PAS entrer dans le nombre annoncé en première ligne : ce
// nombre compte des nœuds, et l'agent le vérifie contre ce qu'il a lu. L'y
// ajouter ferait croire à une trame tronquée à chaque envoi.
//
// Vérifié sur la composition telle que handleListCores l'assemble, faute de
// pouvoir en appeler le corps sans base ni session.
func TestLaCadenceEstEnQueueEtHorsDuCompte(t *testing.T) {
	lignesNoeuds := []string{
		"core-a|10.0.0.1|8443|core|1|SHA256:AAA",
		"core-b|10.0.0.2|8443|proxy|2|SHA256:BBB",
	}

	contenu := []string{strconv.Itoa(len(lignesNoeuds))}
	contenu = append(contenu, strings.Join(lignesNoeuds, "\n"))
	if cadence := ligneCadenceDecouverte(); cadence != "" {
		contenu = append(contenu, cadence)
	}

	lignes := strings.Split(strings.Join(contenu, "\n"), "\n")

	if lignes[0] != strconv.Itoa(len(lignesNoeuds)) {
		t.Fatalf("première ligne = %q, attendu le nombre de nœuds %d",
			lignes[0], len(lignesNoeuds))
	}
	for i, attendu := range lignesNoeuds {
		if lignes[1+i] != attendu {
			t.Fatalf("ligne %d = %q, attendu %q : une ligne insérée avant les nœuds "+
				"casse l'analyse positionnelle de l'agent", 1+i, lignes[1+i], attendu)
		}
	}
	derniere := lignes[len(lignes)-1]
	if !strings.HasPrefix(derniere, PrefixeCadenceDecouverte) {
		t.Fatalf("dernière ligne = %q, attendu un %q", derniere, PrefixeCadenceDecouverte)
	}
	for _, l := range lignes[1 : len(lignes)-1] {
		if strings.HasPrefix(l, PrefixeCadenceDecouverte) {
			t.Fatalf("cadence trouvée ailleurs qu'en queue : %q", l)
		}
	}
}
