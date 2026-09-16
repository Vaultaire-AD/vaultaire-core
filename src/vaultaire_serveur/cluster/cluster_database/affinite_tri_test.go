package clusterdatabase

import (
	"testing"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// L'affinité dans le tri — lot 6 du point 38.
//
// Ces tests portent sur la seule partie qui décide : l'ORDRE. La lecture en base
// demanderait une base, donc ne serait jamais lancée ; le tri s'éprouve avec
// quelques nœuds écrits à la main, et c'est lui que tout le parc suit.

// affin construit un nœud avec son rôle, sa priorité et son affinité.
func affin(nom, role string, priorite int, affin bool) clusterstorage.Node {
	return clusterstorage.Node{Hostname: nom, Role: role, Priorite: priorite, Affin: affin}
}

// TestOrdreCompletDeLaSpecification.
//
// LE test du lot : proxies affins, autres proxies, cores affins, autres cores.
// C'est l'ordre écrit dans l'arbitrage 5 du point 38, et il tient en une ligne
// parce que chacun de ses quatre termes est une décision distincte.
func TestOrdreCompletDeLaSpecification(t *testing.T) {
	noeuds := []clusterstorage.Node{
		affin("core-quelconque", "core", 0, false),
		affin("proxy-quelconque", "proxy", 0, false),
		affin("core-affin", "core", 0, true),
		affin("proxy-affin", "proxy", 0, true),
	}
	TrierNoeudsPourAgents(noeuds)

	attendu := []string{"proxy-affin", "proxy-quelconque", "core-affin", "core-quelconque"}
	if !memeOrdre(ordre(noeuds), attendu) {
		t.Errorf("ordre = %v, attendu %v", ordre(noeuds), attendu)
	}
}

// TestUnCoreAffinNePasseJamaisDevantUnProxy.
//
// L'affinité départage entre PAIRS, jamais entre rôles. Le rôle décide de la
// nature du chemin — passer par un relais ou aller au serveur — et un core affin
// qui doublerait un proxy quelconque viderait les proxies de leur raison d'être
// sur tous les sites qui n'ont pas le leur.
func TestUnCoreAffinNePasseJamaisDevantUnProxy(t *testing.T) {
	noeuds := []clusterstorage.Node{
		affin("core-affin", "core", 1, true),
		affin("proxy-lointain", "proxy", 99, false),
	}
	TrierNoeudsPourAgents(noeuds)

	if ordre(noeuds)[0] != "proxy-lointain" {
		t.Errorf("premier = %q, attendu le proxy : l'affinité ne doit pas franchir le rôle",
			ordre(noeuds)[0])
	}
}

// TestLAffiniteLEmporteSurLaPriorite.
//
// La priorité est un réglage GLOBAL, l'affinité est locale au demandeur. Si la
// priorité l'emportait, un proxy mis en tête pour un site passerait devant le
// proxy local de tous les autres sites : régler un site déréglerait les autres,
// ce qui est exactement ce que l'affinité existe pour éviter.
func TestLAffiniteLEmporteSurLaPriorite(t *testing.T) {
	noeuds := []clusterstorage.Node{
		affin("proxy-prioritaire", "proxy", 1, false),
		affin("proxy-du-site", "proxy", 50, true),
	}
	TrierNoeudsPourAgents(noeuds)

	if ordre(noeuds)[0] != "proxy-du-site" {
		t.Errorf("premier = %q, attendu proxy-du-site : l'affinité passe avant la priorité",
			ordre(noeuds)[0])
	}
}

// TestLaPrioriteDepartageEntreNoeudsEgalementAffins.
//
// L'affinité est un OUI/NON : elle ne classe pas les affins entre eux. Deux
// proxies du même site se départagent donc par la priorité, comme avant.
func TestLaPrioriteDepartageEntreNoeudsEgalementAffins(t *testing.T) {
	noeuds := []clusterstorage.Node{
		affin("proxy-b", "proxy", 20, true),
		affin("proxy-a", "proxy", 10, true),
	}
	TrierNoeudsPourAgents(noeuds)

	attendu := []string{"proxy-a", "proxy-b"}
	if !memeOrdre(ordre(noeuds), attendu) {
		t.Errorf("ordre = %v, attendu %v", ordre(noeuds), attendu)
	}
}

// TestUneAffinitePreferePasExclut.
//
// LE point qui empêche l'affinité de devenir une panne. Tous les nœuds exposés
// restent dans la liste, en queue : un agent dont le proxy local est tombé
// descend et finit par joindre un core. Une exclusivité l'aurait laissé sans
// personne à joindre — la panne d'un relais deviendrait une panne
// d'authentification pour tout le site.
func TestUneAffinitePreferePasExclut(t *testing.T) {
	noeuds := []clusterstorage.Node{
		affin("proxy-du-site", "proxy", 0, true),
		affin("proxy-autre-site", "proxy", 0, false),
		affin("core", "core", 0, false),
	}
	TrierNoeudsPourAgents(noeuds)

	if len(noeuds) != 3 {
		t.Fatalf("%d nœud(s) après tri, attendu 3 : le tri ne doit RIEN retirer", len(noeuds))
	}
	if ordre(noeuds)[2] != "core" {
		t.Errorf("dernier = %q, attendu core : les cores restent joignables en queue",
			ordre(noeuds)[2])
	}
}

// TestSansAffiniteLOrdreEstCeluiDAvantLeLot6.
//
// Garantie de non-régression : un parc qui ne déclare aucune affinité — c'est-à-
// dire tous les parcs le jour de la mise à jour — garde exactement l'ordre qu'il
// avait.
func TestSansAffiniteLOrdreEstCeluiDAvantLeLot6(t *testing.T) {
	noeuds := []clusterstorage.Node{
		affin("core2", "core", 0, false),
		affin("proxy2", "proxy", 5, false),
		affin("proxy1", "proxy", 1, false),
		affin("core1", "core", 0, false),
	}
	TrierNoeudsPourAgents(noeuds)

	attendu := []string{"proxy1", "proxy2", "core1", "core2"}
	if !memeOrdre(ordre(noeuds), attendu) {
		t.Errorf("ordre = %v, attendu %v", ordre(noeuds), attendu)
	}
}

// TestPartageUnGroupe.
//
// L'intersection décide de l'affinité. Un faux négatif rendrait le lot 6 inerte
// sans qu'aucune erreur ne le dise ; un faux positif rendrait tous les nœuds
// affins, donc l'affinité sans effet — les deux se lisent « ça ne marche pas »
// et n'ont pas la même cause.
func TestPartageUnGroupe(t *testing.T) {
	cas := []struct {
		nom     string
		a, b    []int
		attendu bool
	}{
		{"un groupe commun", []int{1, 2}, []int{2, 3}, true},
		{"aucun commun", []int{1, 2}, []int{3, 4}, false},
		{"nœud sans groupe", nil, []int{1}, false},
		{"agent sans groupe", []int{1}, nil, false},
		{"les deux sans groupe", nil, nil, false},
		{"identiques", []int{7}, []int{7}, true},
	}
	for _, c := range cas {
		if got := partageUnGroupe(c.a, c.b); got != c.attendu {
			t.Errorf("%s : partageUnGroupe(%v, %v) = %v, attendu %v",
				c.nom, c.a, c.b, got, c.attendu)
		}
	}
}

// TestMotifDExclusionNommeLaPremiereCause.
//
// Un nœud peut cumuler les causes. N'en corriger qu'une laisserait le nœud
// toujours absent, ce qui se lit comme « la correction n'a rien fait ». Le motif
// nomme la première, et la suivante apparaît une fois celle-là levée.
func TestMotifDExclusionNommeLaPremiereCause(t *testing.T) {
	// Joignable : aucun motif.
	bon := clusterstorage.Node{
		Role: "proxy", Status: "online", ExposeAuxAgents: true,
		Port: 6666, Empreinte: "SHA256:x",
	}
	if motif := motifDExclusion(bon); motif != "" {
		t.Errorf("un nœud joignable est déclaré écarté : %q", motif)
	}

	// Hors rotation ET sans empreinte : c'est la rotation qui est nommée,
	// puisqu'elle est vérifiée d'abord.
	cumul := clusterstorage.Node{
		Role: "proxy", Status: "online", ExposeAuxAgents: false,
		Port: 6666, Empreinte: "",
	}
	if motif := motifDExclusion(cumul); motif == "" {
		t.Error("un nœud hors rotation est déclaré joignable")
	}

	// Un port PUBLIC suffit, même sans port déclaré par le nœud : c'est le seul
	// moyen de remettre dans la liste un nœud enregistré par une version
	// antérieure, sans attendre qu'il se réenregistre.
	portPublic := clusterstorage.Node{
		Role: "core", Status: "online", ExposeAuxAgents: true,
		Port: 0, PortPublic: 16666, Empreinte: "SHA256:x",
	}
	if motif := motifDExclusion(portPublic); motif != "" {
		t.Errorf("un nœud à port public est déclaré écarté : %q", motif)
	}
}
