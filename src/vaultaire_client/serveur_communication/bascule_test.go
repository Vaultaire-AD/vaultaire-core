package serveurcommunication

import (
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/decouverte"
)

// La bascule coupe un tunnel qui fonctionne. Chacun de ces cas est une
// situation où l'agent aurait tort de le faire — ou tort de s'en abstenir.

func noeud(hostname, ip string, port, priorite int) decouverte.Noeud {
	return decouverte.Noeud{
		Hostname: hostname, IP: ip, Port: port,
		Role: "core", Priorite: priorite,
	}
}

func TestDecisionDeBascule(t *testing.T) {
	a := noeud("core-a", "10.0.0.1", 8443, 1)
	b := noeud("core-b", "10.0.0.2", 8443, 2)
	c := noeud("core-c", "10.0.0.3", 8443, 2)
	sansPriorite := noeud("core-z", "10.0.0.9", 8443, 0)

	cas := []struct {
		nom      string
		noeuds   []decouverte.Noeud
		courante string
		basculer bool
		pourquoi string
	}{
		{
			nom:      "déjà sur le nœud prioritaire",
			noeuds:   []decouverte.Noeud{a, b},
			courante: a.Adresse(),
			basculer: false,
			pourquoi: "rien à gagner, et une coupure à payer",
		},
		{
			nom:      "un nœud mieux placé est apparu",
			noeuds:   []decouverte.Noeud{a, b},
			courante: b.Adresse(),
			basculer: true,
			pourquoi: "c'est le défaut que la bascule corrige : sans elle, le poste " +
				"reste sur le secours jusqu'au prochain redémarrage",
		},
		{
			nom:      "égalité de priorité",
			noeuds:   []decouverte.Noeud{b, c},
			courante: c.Adresse(),
			basculer: false,
			pourquoi: "deux nœuds équivalents : basculer de l'un vers l'autre à " +
				"chaque 04_04 ferait un va-et-vient permanent",
		},
		{
			nom:      "le nœud courant a disparu de la liste",
			noeuds:   []decouverte.Noeud{a, b},
			courante: "10.0.0.42:8443",
			basculer: true,
			pourquoi: "retiré du cluster ou plus joignable : c'est justement le " +
				"moment de partir",
		},
		{
			nom:      "liste vide",
			noeuds:   nil,
			courante: a.Adresse(),
			basculer: false,
			pourquoi: "une liste vide ne dit pas que le nœud courant est mauvais, " +
				"elle dit qu'on ne sait rien",
		},
		{
			nom:      "aucun tunnel établi",
			noeuds:   []decouverte.Noeud{a, b},
			courante: "",
			basculer: false,
			pourquoi: "il n'y a rien à fermer",
		},
		{
			nom:      "un nœud sans priorité déclarée ne prend pas la tête",
			noeuds:   []decouverte.Noeud{sansPriorite, b},
			courante: b.Adresse(),
			basculer: false,
			pourquoi: "priorité 0 vaut « dernier » côté core ; la lire comme " +
				"« premier » provoquerait une bascule permanente vers lui",
		},
		{
			nom:      "un nœud sans priorité bascule vers un nœud classé",
			noeuds:   []decouverte.Noeud{sansPriorite, b},
			courante: sansPriorite.Adresse(),
			basculer: true,
			pourquoi: "le nœud courant est en queue, un nœud classé est disponible",
		},
	}

	for _, k := range cas {
		t.Run(k.nom, func(t *testing.T) {
			raison, basculer := DecisionDeBascule(k.noeuds, k.courante)
			if basculer != k.basculer {
				t.Errorf("bascule = %v, attendu %v (%s) — raison donnée : %q",
					basculer, k.basculer, k.pourquoi, raison)
			}
		})
	}
}

// Savoir POURQUOI on n'a pas basculé est ce qu'on cherchera le jour où l'on
// croira qu'on aurait dû. Une décision muette renverrait à relire le code.
func TestChaqueDecisionSExplique(t *testing.T) {
	a := noeud("core-a", "10.0.0.1", 8443, 1)
	b := noeud("core-b", "10.0.0.2", 8443, 2)

	for _, k := range []struct {
		nom      string
		noeuds   []decouverte.Noeud
		courante string
	}{
		{"conservation", []decouverte.Noeud{a, b}, a.Adresse()},
		{"bascule", []decouverte.Noeud{a, b}, b.Adresse()},
		{"liste vide", nil, a.Adresse()},
	} {
		raison, _ := DecisionDeBascule(k.noeuds, k.courante)
		if strings.TrimSpace(raison) == "" {
			t.Errorf("%s : décision sans explication", k.nom)
		}
	}
}

// EvaluerBascule ne doit fermer le tunnel QUE lorsque la décision le dit : la
// séparation entre décider et agir n'aurait aucune valeur si l'action partait
// de toute façon.
func TestSeuleUneDecisionDeBasculeFermeLeTunnel(t *testing.T) {
	a := noeud("core-a", "10.0.0.1", 8443, 1)
	b := noeud("core-b", "10.0.0.2", 8443, 2)

	ferme := 0
	ancien := fermerTunnelMachine
	fermerTunnelMachine = func() { ferme++ }
	t.Cleanup(func() { fermerTunnelMachine = ancien })

	EvaluerBascule([]decouverte.Noeud{a, b}, a.Adresse())
	if ferme != 0 {
		t.Fatalf("tunnel fermé alors que le nœud courant est le meilleur")
	}

	EvaluerBascule([]decouverte.Noeud{a, b}, b.Adresse())
	if ferme != 1 {
		t.Fatalf("tunnel fermé %d fois, attendu 1", ferme)
	}
}
