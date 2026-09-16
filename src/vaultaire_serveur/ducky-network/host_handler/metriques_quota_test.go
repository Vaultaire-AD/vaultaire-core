package hosthandler

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Le quota de métriques par nœud.
//
// Le temps est déplacé plutôt qu'attendu : un test qui dormirait une minute pour
// éprouver une fenêtre d'une minute ne serait plus lancé au bout d'une semaine.

// avecHorlogeFictive installe une horloge que le test pilote, et la retire.
func avecHorlogeFictive(t *testing.T) *time.Time {
	t.Helper()
	base := time.Date(2026, 8, 14, 20, 0, 0, 0, time.UTC)
	horloge := base

	ancienne := maintenantQuota
	maintenantQuota = func() time.Time { return horloge }
	ReinitialiserQuotaMetriques()

	t.Cleanup(func() {
		maintenantQuota = ancienne
		ReinitialiserQuotaMetriques()
	})
	return &horloge
}

// TestLeQuotaCoupeAuSeuilEtPasAvant.
//
// Les deux bornes comptent. Couper trop tôt refuserait des métriques légitimes ;
// couper trop tard laisserait passer une fois de trop, ce qui ne se verrait
// jamais sur un compteur de soixante.
func TestLeQuotaCoupeAuSeuilEtPasAvant(t *testing.T) {
	avecHorlogeFictive(t)

	for i := 1; i <= QuotaMetriquesParFenetre; i++ {
		if !AutoriseMetrique("proxy-01") {
			t.Fatalf("métrique %d refusée alors que le quota est de %d",
				i, QuotaMetriquesParFenetre)
		}
	}
	if AutoriseMetrique("proxy-01") {
		t.Errorf("la métrique %d est acceptée : le quota ne coupe pas",
			QuotaMetriquesParFenetre+1)
	}
}

// TestLaFenetreSuivanteRepartDeZero.
//
// C'est ce qui distingue un plafond d'un verrou. Un nœud qui a dépassé doit
// redevenir normal tout seul, sans intervention et sans reconnexion.
func TestLaFenetreSuivanteRepartDeZero(t *testing.T) {
	horloge := avecHorlogeFictive(t)

	for i := 0; i < QuotaMetriquesParFenetre+10; i++ {
		AutoriseMetrique("proxy-01")
	}
	if AutoriseMetrique("proxy-01") {
		t.Fatal("le quota ne coupe pas dans la première fenêtre")
	}

	*horloge = horloge.Add(FenetreQuotaMetriques)

	if !AutoriseMetrique("proxy-01") {
		t.Error("la fenêtre suivante refuse encore : le quota se comporte " +
			"comme un verrou, pas comme un plafond")
	}
}

// TestUnNoeudNeConsommePasLeQuotaDUnAutre.
//
// Le compteur est PAR nœud. Un compteur global laisserait un proxy bavard faire
// abandonner les métriques de tous les autres — c'est-à-dire transformer un
// nœud déréglé en panne d'observabilité pour le parc entier.
func TestUnNoeudNeConsommePasLeQuotaDUnAutre(t *testing.T) {
	avecHorlogeFictive(t)

	for i := 0; i < QuotaMetriquesParFenetre+5; i++ {
		AutoriseMetrique("proxy-bavard")
	}
	if AutoriseMetrique("proxy-bavard") {
		t.Fatal("le quota ne coupe pas")
	}

	if !AutoriseMetrique("proxy-tranquille") {
		t.Error("un second nœud est refusé alors qu'il n'a rien émis")
	}
}

// TestLaFenetreSeMesureDepuisSonDebut.
//
// Une fenêtre qui repartirait à chaque appel — en glissant — ne se fermerait
// jamais pour un nœud qui émet en continu, donc n'aurait plus aucun effet.
func TestLaFenetreSeMesureDepuisSonDebut(t *testing.T) {
	horloge := avecHorlogeFictive(t)

	// Un appel, puis on avance juste en dessous de la fenêtre.
	AutoriseMetrique("proxy-01")
	*horloge = horloge.Add(FenetreQuotaMetriques - time.Millisecond)

	for i := 1; i < QuotaMetriquesParFenetre; i++ {
		if !AutoriseMetrique("proxy-01") {
			t.Fatalf("métrique %d refusée avant le seuil", i+1)
		}
	}
	if AutoriseMetrique("proxy-01") {
		t.Error("le seuil n'est pas atteint : la fenêtre a glissé au lieu " +
			"de se mesurer depuis son début")
	}
}

// TestLaCarteNeGrossitPasIndefiniment.
//
// Sans purge, une entrée par nœud ayant jamais émis une métrique subsiste — une
// fuite lente, sur un serveur qui tourne des mois.
func TestLaCarteNeGrossitPasIndefiniment(t *testing.T) {
	horloge := avecHorlogeFictive(t)

	for i := 0; i < 300; i++ {
		AutoriseMetrique("noeud-" + itoa(i))
	}
	avant := len(quotaParNoeud)

	// Bien au-delà du seuil de péremption, puis un appel qui déclenche la purge.
	*horloge = horloge.Add(11 * FenetreQuotaMetriques)
	AutoriseMetrique("noeud-neuf")

	if len(quotaParNoeud) >= avant {
		t.Errorf("la carte est passée de %d à %d entrées : rien n'est purgé",
			avant, len(quotaParNoeud))
	}
}

// TestItoa : la conversion sert dans un message de journal, et une erreur y
// afficherait un compte faux sans que rien ne le signale.
func TestItoa(t *testing.T) {
	cas := map[int]string{0: "0", 1: "1", 9: "9", 10: "10", 60: "60", 12345: "12345"}
	for n, attendu := range cas {
		if got := itoa(n); got != attendu {
			t.Errorf("itoa(%d) = %q, attendu %q", n, got, attendu)
		}
	}
}

// lireSourceHandler rend le texte de handler.go.
//
// Le test qui suit inspecte la SOURCE plutôt que le comportement : le
// gestionnaire exige une base et une session Ducky, et l'éprouver en vrai
// demanderait de monter les deux pour vérifier une propriété qui se lit en trois
// lignes.
func lireSourceHandler(t *testing.T) string {
	t.Helper()
	contenu, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("lecture de handler.go : %v", err)
	}
	return string(contenu)
}

// TestLeRefusEstNonPunitifDansLeHandler.
//
// Garde-fou de la décision la plus facile à défaire par inadvertance : le
// dépassement ne doit ni fermer la connexion ni remonter une erreur. Punir un
// nœud bavard couperait aussi son enregistrement et son battement, donc le
// retirerait de la liste servie aux agents — la sanction serait pire que le
// problème.
//
// Le test lit la source parce que le handler exige une base et une session.
func TestLeRefusEstNonPunitifDansLeHandler(t *testing.T) {
	source := lireSourceHandler(t)

	i := strings.Index(source, "if !AutoriseMetrique(proprietaire)")
	if i < 0 {
		t.Fatal("handleProxyMetrics n'appelle plus AutoriseMetrique")
	}
	bloc := source[i:min(i+400, len(source))]

	if !strings.Contains(bloc, "04_06") {
		t.Error("le dépassement ne répond pas 04_06 : le nœud resterait sans réponse")
	}
	if strings.Contains(bloc, "fmt.Errorf") {
		t.Error("le dépassement remonte une erreur : elle ferait fermer la connexion " +
			"du nœud, donc couperait son enregistrement et son battement")
	}
	if !strings.Contains(bloc, "throttled") {
		t.Error("le dépassement accuse réception comme si la métrique avait été " +
			"écrite : la réponse doit dire ce qui s'est passé")
	}
}
