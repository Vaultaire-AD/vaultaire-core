package commandaction

import (
	"errors"
	"strings"
	"testing"

	"vaultaire/core/action"
)

// TestParamsDepuisPositionnelsNePaniquePas est le test du défaut qui a motivé
// cette fonction.
//
// Les commandes lisaient leurs arguments par indice :
//
//	username := command_list[1]
//	domain   := command_list[2]
//
// C'est ainsi qu'est né le dépassement d'indice de « create -g » : la garde
// vérifiait `len < 2` et le corps lisait l'indice 2. Une goroutine qui panique
// arrête le processus ENTIER — pas seulement la commande.
func TestParamsDepuisPositionnelsNePaniquePas(t *testing.T) {
	cas := []struct {
		nom     string
		args    []string
		attendu map[string]string
	}{
		{
			"tous présents",
			[]string{"alice", "paris.fr"},
			map[string]string{"group": "alice", "domain": "paris.fr"},
		},
		{
			// Le cas exact du bug : un argument manquant.
			"un seul argument pour deux noms",
			[]string{"monGroupe"},
			map[string]string{"group": "monGroupe"},
		},
		{
			"aucun argument",
			[]string{},
			map[string]string{},
		},
		{
			// Les arguments en trop sont ignorés plutôt que de faire échouer :
			// l'action validera ce qu'elle a reçu.
			"plus d'arguments que de noms",
			[]string{"a", "b", "c", "d"},
			map[string]string{"group": "a", "domain": "b"},
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			p := ParamsDepuisPositionnels(c.args, "group", "domain")
			if len(p) != len(c.attendu) {
				t.Fatalf("%d paramètres, attendu %d : %v", len(p), len(c.attendu), p)
			}
			for k, v := range c.attendu {
				if p[k] != v {
					t.Errorf("%s = %q, attendu %q", k, p[k], v)
				}
			}
		})
	}
}

// TestArgumentVideEstTraiteCommeAbsent.
//
// « create -u "" paris.fr » ne doit pas créer un compte au nom vide. Le
// paramètre est omis, et l'action rend « identifiant requis » — un message qui
// désigne le problème, là où un nom vide aurait produit un compte inutilisable
// dont personne n'aurait compris l'origine.
func TestArgumentVideEstTraiteCommeAbsent(t *testing.T) {
	p := ParamsDepuisPositionnels([]string{"", "paris.fr"}, "username", "domain")
	if _, present := p["username"]; present {
		t.Fatal("un argument vide produit un paramètre présent : " +
			"un compte au nom vide pourrait être créé")
	}
	if p["domain"] != "paris.fr" {
		t.Fatalf("domain = %q : les arguments suivants sont décalés", p["domain"])
	}
}

// TestArgumentAvecEspacesConserveSaValeur.
//
// Le nettoyage sert à détecter l'absence, PAS à modifier la valeur transmise :
// un mot de passe entouré d'espaces doit arriver intact à l'action, sinon
// l'utilisateur ne pourra pas se connecter avec ce qu'il a saisi.
func TestArgumentAvecEspacesConserveSaValeur(t *testing.T) {
	p := ParamsDepuisPositionnels([]string{"  secret  "}, "password")
	if p["password"] != "  secret  " {
		t.Fatalf("password = %q : la valeur a été modifiée en chemin", p["password"])
	}
}

// TestVocabulaireDEchecPreserve.
//
// deployments/pre-prod/scripts/rbac_fixture.sh détecte les échecs en cherchant
// « erreur|refus|introuvable|invalide » dans la sortie de vlt. Un message
// d'échec qui n'en contiendrait aucun ferait passer l'échec pour un succès dans
// ce script — silencieusement, ce qui est le pire cas pour un script de
// vérification.
func TestVocabulaireDEchecPreserve(t *testing.T) {
	motsAttendus := []string{"erreur", "refus", "introuvable", "invalide"}

	cas := map[string]error{
		"refus de droit": &action.ErrRefusee{
			Action: "user.create", Cle: "write:create:user", Motif: "droit absent",
		},
		"action inconnue": &action.ErrInconnue{Nom: "user.inexistante"},
		"échec métier":    errors.New("la base est injoignable"),
	}

	for nom, err := range cas {
		t.Run(nom, func(t *testing.T) {
			msg := strings.ToLower(MessageDErreur(err))
			trouve := false
			for _, mot := range motsAttendus {
				if strings.Contains(msg, mot) {
					trouve = true
					break
				}
			}
			if !trouve {
				t.Fatalf("message %q : ne contient aucun de %v — "+
					"rbac_fixture.sh le prendrait pour un succès", msg, motsAttendus)
			}
		})
	}
}

// TestRefusEtEchecSeDistinguent.
//
// « Permission refusée » et « Erreur » ne veulent pas dire la même chose pour
// qui lit la sortie : le premier appelle une vérification des droits, le second
// un examen de l'état du système. Les confondre envoie chercher au mauvais
// endroit.
func TestRefusEtEchecSeDistinguent(t *testing.T) {
	refus := MessageDErreur(&action.ErrRefusee{
		Action: "user.create", Cle: "write:create:user", Motif: "droit absent",
	})
	if !strings.HasPrefix(refus, "Permission refusée") {
		t.Errorf("refus de droit rendu comme %q", refus)
	}

	echec := MessageDErreur(errors.New("la base est injoignable"))
	if strings.HasPrefix(echec, "Permission refusée") {
		t.Errorf("échec métier rendu comme un refus de droit : %q", echec)
	}
}

// TestActionInconnueEstSignaleeCommeInterne.
//
// Une commande qui désigne une action absente du registre est une faute de
// programmation. Le message doit le dire, sinon l'utilisateur cherche du côté
// de la syntaxe qu'il a tapée.
func TestActionInconnueEstSignaleeCommeInterne(t *testing.T) {
	msg := MessageDErreur(&action.ErrInconnue{Nom: "user.inexistante"})
	if !strings.Contains(strings.ToLower(msg), "interne") {
		t.Fatalf("message %q : laisse croire à une erreur de saisie", msg)
	}
	if !strings.Contains(msg, "user.inexistante") {
		t.Errorf("message %q : ne nomme pas l'action manquante", msg)
	}
}

func TestMessageDErreurNilRendVide(t *testing.T) {
	if MessageDErreur(nil) != "" {
		t.Error("une absence d'erreur produit un message")
	}
}

// TestVerifierCatalogueDetecteUneActionAbsente.
//
// Appelée au démarrage : une commande qui désignerait une action absente
// échouerait sinon au moment où quelqu'un la tape, c'est-à-dire au plus mauvais
// moment.
func TestVerifierCatalogueDetecteUneActionAbsente(t *testing.T) {
	action.EnregistrerTout()

	if err := VerifierCatalogue([]string{"user.create", "group.create"}); err != nil {
		t.Fatalf("actions existantes signalées absentes : %v", err)
	}

	err := VerifierCatalogue([]string{"user.create", "action.inventee"})
	if err == nil {
		t.Fatal("action absente non détectée")
	}
	if !strings.Contains(err.Error(), "action.inventee") {
		t.Errorf("message %q : ne nomme pas l'action manquante", err.Error())
	}
}

// TestFusionnerParamsNeperdRien : les options longues complètent les
// positionnels sans les écraser silencieusement.
func TestFusionnerParams(t *testing.T) {
	base := action.Params{"name": "politique-ssh", "scope": "machine"}
	fusion := FusionnerParams(base, action.Params{"desc": "règles SSH"})

	if fusion["name"] != "politique-ssh" || fusion["scope"] != "machine" {
		t.Fatal("la fusion a perdu des valeurs positionnelles")
	}
	if fusion["desc"] != "règles SSH" {
		t.Fatal("la fusion n'a pas ajouté l'option longue")
	}

	// Sur une base nil, la fusion doit produire une map utilisable plutôt que
	// de paniquer à l'écriture.
	if got := FusionnerParams(nil, action.Params{"a": "b"}); got["a"] != "b" {
		t.Fatal("fusion sur une base nil perdue")
	}
}
