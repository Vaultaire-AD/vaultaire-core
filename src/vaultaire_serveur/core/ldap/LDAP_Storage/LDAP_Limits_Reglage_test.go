package ldapstorage

import (
	"strings"
	"testing"
)

// TO-DO 152 : les bornes se règlent dans `ldap.limites`. Ce qui s'éprouve ici,
// c'est qu'aucune ne peut être retirée par accident.

// sauvegarderLesBornes remet toutes les bornes à leur valeur d'avant le test.
func sauvegarderLesBornes(t *testing.T) {
	t.Helper()
	bornes := bornesReglables()
	avant := make([]int, len(bornes))
	for i, b := range bornes {
		avant[i] = *b.cible
	}
	t.Cleanup(func() {
		for i, b := range bornes {
			*b.cible = avant[i]
		}
	})
}

func TestLesBornesSeReglent(t *testing.T) {
	sauvegarderLesBornes(t)

	err := AppliquerLimites(map[string]int{
		"max_search_entries":       2000,
		"max_page_size":            500,
		"paged_cursor_ttl_seconds": 60,
	})
	if err != nil {
		t.Fatalf("réglage valide refusé : %v", err)
	}
	if MaxSearchEntries != 2000 || MaxPageSize != 500 || PagedCursorTTLSeconds != 60 {
		t.Errorf("bornes posées : %d, %d, %d — attendu 2000, 500, 60",
			MaxSearchEntries, MaxPageSize, PagedCursorTTLSeconds)
	}
	// Une clé absente garde sa valeur.
	if MaxPagedSearchEntries != 200000 {
		t.Errorf("max_paged_search_entries a bougé sans avoir été écrit : %d", MaxPagedSearchEntries)
	}
}

// LE test du point : zéro et les valeurs négatives DÉSACTIVENT une borne dans
// le code. Depuis le fichier, ils sont refusés — toutes clés confondues.
func TestAucuneBorneNeSeDesactiveDepuisLeFichier(t *testing.T) {
	sauvegarderLesBornes(t)

	for _, cle := range ClesDesLimites() {
		for _, v := range []int{0, -1} {
			err := AppliquerLimites(map[string]int{cle: v})
			if err == nil {
				t.Errorf("%s: %d accepté — une protection serait retirée par une saisie", cle, v)
				continue
			}
			if !strings.Contains(err.Error(), cle) {
				t.Errorf("%s: %d — le refus ne nomme pas la clé : %v", cle, v, err)
			}
		}
	}
}

func TestUnOrdreDeGrandeurAberrantEstRefuse(t *testing.T) {
	sauvegarderLesBornes(t)

	for _, b := range bornesReglables() {
		if err := AppliquerLimites(map[string]int{b.cle: b.max + 1}); err == nil {
			t.Errorf("%s: %d accepté, au-delà du plafond %d", b.cle, b.max+1, b.max)
		}
	}
}

// Une clé mal orthographiée ne règle rien : la laisser passer ferait lire dans
// le fichier une borne qui n'existe pas.
func TestUneCleInconnueEstUneErreur(t *testing.T) {
	sauvegarderLesBornes(t)

	err := AppliquerLimites(map[string]int{"max_page_sizes": 500})
	if err == nil {
		t.Fatal("clé inconnue acceptée en silence")
	}
	if !strings.Contains(err.Error(), "max_page_size") {
		t.Errorf("le refus ne liste pas les clés admises : %v", err)
	}
}

// TOUT OU RIEN : une valeur refusée ne laisse pas l'autre posée.
func TestUnReglageRefuseNePoseRien(t *testing.T) {
	sauvegarderLesBornes(t)
	avant := MaxSearchEntries

	err := AppliquerLimites(map[string]int{
		"max_search_entries": 5000,
		"max_page_size":      0,
	})
	if err == nil {
		t.Fatal("réglage accepté alors qu'une des deux valeurs est refusée")
	}
	if MaxSearchEntries != avant {
		t.Errorf("max_search_entries posé à %d alors que le réglage a été refusé : "+
			"le serveur tournerait avec la moitié d'un fichier", MaxSearchEntries)
	}
}

// Les bornes se contraignent entre elles : trois saisies qui, chacune valable
// seule, rendent l'ensemble incohérent.
func TestLesBornesIncoherentesEntreEllesSontRefusees(t *testing.T) {
	for nom, valeurs := range map[string]map[string]int{
		"paginer rend moins qu'une recherche ordinaire": {
			"max_search_entries": 50000, "max_paged_search_entries": 20000},
		"la plus grande recherche paginée est toujours refusée": {
			"max_paged_search_entries": 300000, "max_paged_entries_held": 100000},
		"une page plus grande que la recherche entière": {
			"max_search_entries": 100, "max_paged_search_entries": 500,
			"max_paged_entries_held": 500, "max_page_size": 1000},
	} {
		t.Run(nom, func(t *testing.T) {
			sauvegarderLesBornes(t)
			if err := AppliquerLimites(valeurs); err == nil {
				t.Errorf("accepté : %v", valeurs)
			}
		})
	}
}

// Les valeurs LIVRÉES passent leurs propres contrôles : sans cela, écrire les
// défauts dans le fichier — ce que fait le fichier de référence — arrêterait
// le démarrage.
func TestLesValeursParDefautSontAdmises(t *testing.T) {
	sauvegarderLesBornes(t)

	defauts := map[string]int{}
	for _, b := range bornesReglables() {
		defauts[b.cle] = *b.cible
	}
	if err := AppliquerLimites(defauts); err != nil {
		t.Fatalf("les valeurs par défaut sont refusées par leurs propres bornes : %v", err)
	}
	if err := AppliquerLimites(nil); err != nil {
		t.Fatalf("section absente refusée : %v", err)
	}
}
