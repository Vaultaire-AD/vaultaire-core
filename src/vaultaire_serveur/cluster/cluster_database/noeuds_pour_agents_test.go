package clusterdatabase

import (
	"testing"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// L'ordre de la liste servie aux agents.
//
// # Pourquoi ce tri mérite ses propres tests
//
// C'est ce sur quoi TOUT LE PARC s'appuie pour choisir qui joindre. Un défaut
// n'y produit aucune erreur : les agents se connectent quand même, simplement au
// mauvais endroit — tous au même core alors qu'un proxy attend, ou en ordre
// changeant d'une requête à l'autre.
//
// La lecture en base n'est pas éprouvée ici. Elle demanderait une base, donc ne
// serait jamais lancée ; le tri, lui, s'éprouve avec quatre nœuds écrits à la
// main. C'est la partie qui décide.

func noeud(nom, role string, priorite int) clusterstorage.Node {
	return clusterstorage.Node{Hostname: nom, Role: role, Priorite: priorite}
}

func ordre(noeuds []clusterstorage.Node) []string {
	out := make([]string, 0, len(noeuds))
	for _, n := range noeuds {
		out = append(out, n.Hostname)
	}
	return out
}

func memeOrdre(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestLesProxiesPassentDevant.
//
// C'est leur raison d'être. Un parc qui en déploie veut que les agents y
// passent, sinon ils ne servent à rien.
func TestLesProxiesPassentDevant(t *testing.T) {
	noeuds := []clusterstorage.Node{
		noeud("core1", "core", 0),
		noeud("proxy1", "proxy", 0),
		noeud("core2", "core", 0),
		noeud("proxy2", "proxy", 0),
	}
	TrierNoeudsPourAgents(noeuds)

	attendu := []string{"proxy1", "proxy2", "core1", "core2"}
	if !memeOrdre(ordre(noeuds), attendu) {
		t.Errorf("ordre = %v, attendu %v", ordre(noeuds), attendu)
	}
}

// TestLesCoresRestentDansLaListe.
//
// Un client dont tous les proxies échouent doit pouvoir joindre un core, sans
// quoi la panne d'un relais deviendrait une panne d'authentification pour toutes
// les machines qui l'utilisent.
func TestLesCoresRestentDansLaListe(t *testing.T) {
	noeuds := []clusterstorage.Node{
		noeud("proxy1", "proxy", 0),
		noeud("core1", "core", 0),
	}
	TrierNoeudsPourAgents(noeuds)

	trouve := false
	for _, n := range noeuds {
		if n.Role == "core" {
			trouve = true
		}
	}
	if !trouve {
		t.Error("aucun core dans la liste triée")
	}
}

// TestUnePrioriteNulleSeRangeApres.
//
// LE piège de ce tri, et il se paie une fois en production. Une priorité nulle
// vaut « sans préférence ». Si elle se rangeait avant, donner une priorité à un
// seul nœud le reléguerait derrière tous les autres — l'exact inverse de
// l'intention de qui la pose.
func TestUnePrioriteNulleSeRangeApres(t *testing.T) {
	noeuds := []clusterstorage.Node{
		noeud("sans", "core", 0),
		noeud("prioritaire", "core", 1),
	}
	TrierNoeudsPourAgents(noeuds)

	if noeuds[0].Hostname != "prioritaire" {
		t.Fatalf("ordre = %v : le nœud à qui on a donné une priorité doit passer "+
			"devant ceux qui n'en ont pas", ordre(noeuds))
	}
}

// TestDeuxNoeudsSansPrioriteRestentEgaux.
//
// prioriteEffective ne doit pas rendre MaxInt : deux nœuds sans priorité doivent
// rester ÉGAUX entre eux, pour que le départage par nom joue. Sinon leur ordre
// dépendrait de celui de la requête, qui n'est pas garanti.
func TestDeuxNoeudsSansPrioriteRestentEgaux(t *testing.T) {
	if prioriteEffective(0) != prioriteEffective(-3) {
		t.Error("deux priorités « absentes » ne sont pas égales : le départage " +
			"par nom ne jouerait pas entre elles")
	}
	if prioriteEffective(1) >= prioriteEffective(0) {
		t.Error("une priorité explicite ne passe pas devant l'absence de priorité")
	}
}

// TestLOrdreEstReproductible.
//
// Sans départage par nom, deux nœuds de même rôle et même priorité
// s'ordonneraient selon le plan d'exécution : la liste changerait d'une requête
// à l'autre, et tout le parc basculerait ensemble sur un nœud que rien n'a
// désigné.
func TestLOrdreEstReproductible(t *testing.T) {
	depart := []clusterstorage.Node{
		noeud("delta", "core", 0),
		noeud("alpha", "core", 0),
		noeud("charlie", "core", 0),
		noeud("bravo", "core", 0),
	}

	var reference []string
	for i := 0; i < 5; i++ {
		// Copie neuve à chaque passage, dans le même désordre.
		noeuds := append([]clusterstorage.Node(nil), depart...)
		TrierNoeudsPourAgents(noeuds)
		if i == 0 {
			reference = ordre(noeuds)
			continue
		}
		if !memeOrdre(ordre(noeuds), reference) {
			t.Fatalf("passage %d : ordre %v, attendu %v", i, ordre(noeuds), reference)
		}
	}

	attendu := []string{"alpha", "bravo", "charlie", "delta"}
	if !memeOrdre(reference, attendu) {
		t.Errorf("ordre = %v, attendu %v", reference, attendu)
	}
}

// TestLaPrioritePrimeSurLeNomMaisPasSurLeRole : l'ordre des trois critères.
func TestLaPrioritePrimeSurLeNomMaisPasSurLeRole(t *testing.T) {
	noeuds := []clusterstorage.Node{
		noeud("aaa-core", "core", 1),  // priorité forte, mais core
		noeud("zzz-proxy", "proxy", 9), // priorité faible, mais proxy
	}
	TrierNoeudsPourAgents(noeuds)

	if noeuds[0].Role != "proxy" {
		t.Errorf("ordre = %v : le rôle prime sur la priorité", ordre(noeuds))
	}

	noeuds = []clusterstorage.Node{
		noeud("aaa", "core", 9),
		noeud("zzz", "core", 1),
	}
	TrierNoeudsPourAgents(noeuds)
	if noeuds[0].Hostname != "zzz" {
		t.Errorf("ordre = %v : la priorité prime sur le nom", ordre(noeuds))
	}
}
