package passwordpolicy

import (
	"strings"
	"testing"
	"time"
)

// Le point 99 tient à une distinction : un mot de passe provisoire OUVRE la
// session et AVERTIT, un provisoire PÉRIMÉ est un mot de passe expiré. Ces
// tests portent sur cette décision, qui est pure.

func TestUnMotDePasseOrdinaireNeDemandeRien(t *testing.T) {
	o := EvaluerObligation(false, time.Time{}, false, time.Now())
	if o.ADemander || o.Perime {
		t.Errorf("obligation posée sur un compte ordinaire : %+v", o)
	}
	if MessageDeChangement(o) != "" {
		t.Errorf("message présenté à un compte ordinaire : %q", MessageDeChangement(o))
	}
}

// LE test du point : dans sa fenêtre, le provisoire demande sans refuser.
//
// C'est la décision qui distingue ce point d'un simple « mot de passe expiré » :
// refuser la session sur le chemin PAM demanderait de changer son mot de passe
// sans pouvoir ouvrir de session pour le faire. Un employé dont le poste est la
// seule porte d'entrée serait enfermé dehors par la mesure censée le protéger.
func TestDansSaFenetreLeProvisoireDemandeSansRefuser(t *testing.T) {
	maintenant := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	echeance := maintenant.Add(6 * time.Hour)

	o := EvaluerObligation(true, echeance, true, maintenant)
	if !o.ADemander {
		t.Error("le changement n'est pas demandé")
	}
	if o.Perime {
		t.Error("un provisoire encore dans sa fenêtre est déclaré périmé")
	}

	// Et il devient un refus par la seule voie prévue : l'état d'expiration.
	valide := Status{State: StateValid}
	if StatutAvecProvisoire(valide, o).IsExpired() {
		t.Error("un provisoire valide rend le mot de passe expiré")
	}
}

// Passée l'échéance, c'est un mot de passe EXPIRÉ — le même état, donc les
// mêmes refus, sur les quatre chemins qui savent déjà les appliquer.
func TestUnProvisoirePerimeEstUnMotDePasseExpire(t *testing.T) {
	maintenant := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	echeance := maintenant.Add(-time.Minute)

	o := EvaluerObligation(true, echeance, true, maintenant)
	if !o.Perime {
		t.Fatal("l'échéance dépassée ne périme pas le mot de passe")
	}

	statut := StatutAvecProvisoire(Status{State: StateValid}, o)
	if !statut.IsExpired() {
		t.Error("un provisoire périmé n'est pas rendu comme un mot de passe expiré — "+
			"les chemins qui refusent l'expiration ne le refuseront pas", statut.State)
	}
	// L'exemption du compte de dernier recours ne doit pas survivre : elle vise
	// l'ANCIENNETÉ d'un mot de passe, pas un provisoire qu'on a laissé mourir.
	if StatutAvecProvisoire(Status{State: StateValid, Exempt: true}, o).Exempt {
		t.Error("l'exemption survit à un provisoire périmé")
	}
}

// À la seconde exacte de l'échéance, le mot de passe vaut encore.
//
// Le contraire ferait dépendre le résultat de l'arrondi de l'horloge, sur une
// comparaison que deux cores du cluster n'évaluent pas à la même milliseconde —
// donc d'un refus qui dépendrait du core joint.
func TestALEcheanceExacteLeMotDePasseValutEncore(t *testing.T) {
	instant := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	if EvaluerObligation(true, instant, true, instant).Perime {
		t.Error("périmé à la seconde exacte de son échéance")
	}
}

// Sans échéance, le changement reste obligatoire et le mot de passe ne périme
// jamais. C'est le cas du compte d'amorçage : lui poser une échéance
// condamnerait une installation dont personne ne s'est occupé deux jours, sans
// laisser de recours — puisque ce compte EST le recours.
func TestSansEcheanceLeChangementResteObligatoire(t *testing.T) {
	o := EvaluerObligation(true, time.Time{}, false, time.Now())
	if !o.ADemander {
		t.Error("le changement n'est pas demandé")
	}
	if o.Perime {
		t.Error("un provisoire sans échéance est périmé")
	}
	msg := MessageDeChangement(o)
	if msg == "" || strings.Contains(msg, "0001") {
		t.Errorf("message incorrect pour un provisoire sans échéance : %q", msg)
	}
}

// LE canal réutilisable : une seule ligne, quelle qu'en soit la cause.
//
// Un utilisateur dont le mot de passe est à la fois provisoire et bientôt
// expiré n'a pas besoin de deux messages : il a besoin de savoir qu'il doit
// aller sur le portail.
func TestUneSeuleLigneEstPresentee(t *testing.T) {
	provisoire := EvaluerObligation(true, time.Now().Add(time.Hour), true, time.Now())
	preavis := Status{State: StateWarning, DaysUntilExpiry: 5}

	ligne := AvertissementDeConnexion(provisoire, preavis)
	if !strings.Contains(ligne, "provisoire") {
		t.Errorf("le provisoire ne l'emporte pas sur le préavis : %q", ligne)
	}
	if strings.Contains(ligne, "\n") {
		t.Errorf("le message tient sur plusieurs lignes : %q — il traverse une invite "+
			"PAM et un écran de connexion, qui l'affichent tel quel", ligne)
	}

	// Sans provisoire, c'est le préavis d'expiration qui passe — et c'est ce qui
	// rend le dispositif réutilisable : jusqu'ici, ce préavis n'était affiché
	// que sur le portail, c'est-à-dire là où l'utilisateur ne va pas.
	seul := AvertissementDeConnexion(Obligation{}, preavis)
	if !strings.Contains(seul, "5 jours") {
		t.Errorf("le préavis d'expiration ne passe pas : %q", seul)
	}

	// Rien à dire : rien n'est dit. Une ligne vide affichée à chaque connexion
	// apprendrait aux gens à ne plus lire ce canal.
	if AvertissementDeConnexion(Obligation{}, Status{State: StateValid}) != "" {
		t.Error("un message est présenté sans raison")
	}
}

// Le message ne porte JAMAIS de secret : il s'affiche sur un écran de
// connexion, lisible par qui regarde par-dessus l'épaule.
func TestLeMessageNePorteAucunSecret(t *testing.T) {
	o := EvaluerObligation(true, time.Now().Add(time.Hour), true, time.Now())
	msg := AvertissementDeConnexion(o, Status{State: StateValid})

	for _, interdit := range []string{"mot de passe :", "secret", "$argon2", "mfa"} {
		if strings.Contains(strings.ToLower(msg), interdit) {
			t.Errorf("le message contient %q : %q", interdit, msg)
		}
	}
	// Il doit en revanche dire OÙ aller : sans cela, il décrit un problème sans
	// solution, et l'utilisateur appelle le support.
	if !strings.Contains(strings.ToLower(msg), "portail") {
		t.Errorf("le message ne dit pas où changer le mot de passe : %q", msg)
	}
}
