package security

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// empreinteHeritee reproduit l'ancien calcul — SHA-256 de sel‖mot de passe.
//
// Recopié ici volontairement plutôt qu'appelé : le code de production ne doit
// plus savoir PRODUIRE ce format, seulement le relire. Si un jour cette
// fonction disparaissait du code réel sans que les tests en aient une copie,
// on ne pourrait plus fabriquer un compte hérité pour éprouver la migration.
func empreinteHeritee(motDePasse, selHex string) string {
	sel, _ := hex.DecodeString(selHex)
	somme := sha256.Sum256(append(append([]byte{}, sel...), []byte(motDePasse)...))
	return hex.EncodeToString(somme[:])
}

func TestUnMotDePasseHacheSeRelit(t *testing.T) {
	empreinte, sel, err := Hacher("un mot de passe correct")
	if err != nil {
		t.Fatalf("hachage : %v", err)
	}

	valide, aReencoder := Verifier("un mot de passe correct", sel, empreinte)
	if !valide {
		t.Error("le mot de passe correct est refusé")
	}
	if aReencoder {
		t.Error("une empreinte fraîche est signalée comme à réencoder")
	}
}

func TestUnMauvaisMotDePasseEstRefuse(t *testing.T) {
	empreinte, sel, _ := Hacher("le bon")
	if valide, _ := Verifier("le mauvais", sel, empreinte); valide {
		t.Error("un mot de passe faux est accepté")
	}
}

// TestDeuxHachagesDuMemeMotDePasseDiffèrent : sans sel par compte, deux comptes
// portant le même mot de passe auraient la même empreinte — et une seule
// attaque les casserait tous les deux.
func TestDeuxHachagesDuMemeMotDePasseDiffèrent(t *testing.T) {
	a, _, _ := Hacher("identique")
	b, _, _ := Hacher("identique")
	if a == b {
		t.Error("deux hachages du même mot de passe sont identiques : le sel n'est pas aléatoire")
	}
}

// TestUneEmpreinteHeriteeEstRelueEtSignalee — LE test de la migration.
//
// Un compte créé avant la bascule doit continuer à se connecter, ET être
// signalé comme à réencoder. Perdre la première moitié enferme dehors tout le
// parc ; perdre la seconde arrête la migration en silence, et les comptes
// resteraient en SHA-256 indéfiniment sans que rien ne le dise.
func TestUneEmpreinteHeriteeEstRelueEtSignalee(t *testing.T) {
	const sel = "00112233445566778899aabbccddeeff"
	empreinte := empreinteHeritee("mot de passe historique", sel)

	valide, aReencoder := Verifier("mot de passe historique", sel, empreinte)
	if !valide {
		t.Fatal("un compte hérité ne peut plus se connecter")
	}
	if !aReencoder {
		t.Error("une empreinte SHA-256 n'est pas signalée comme à réencoder : la migration ne démarrera jamais")
	}
}

func TestUneEmpreinteHeriteeRefuseLeMauvaisMotDePasse(t *testing.T) {
	const sel = "00112233445566778899aabbccddeeff"
	empreinte := empreinteHeritee("le bon", sel)

	if valide, _ := Verifier("le mauvais", sel, empreinte); valide {
		t.Error("un mot de passe faux est accepté sur une empreinte héritée")
	}
}

// TestLesDeuxFormatsNeSeConfondentPas : c'est ce qui remplace la colonne
// « algorithme ». Une empreinte SHA-256 est 64 caractères hexadécimaux, une
// empreinte argon2id commence par « $ » — aucune ne peut passer pour l'autre.
func TestLesDeuxFormatsNeSeConfondentPas(t *testing.T) {
	moderne, _, _ := Hacher("x")
	heritee := empreinteHeritee("x", "00112233445566778899aabbccddeeff")

	if !strings.HasPrefix(moderne, "$argon2id$") {
		t.Errorf("l'empreinte argon2id ne porte pas son préfixe : %q", moderne)
	}
	if strings.HasPrefix(heritee, "$") {
		t.Error("une empreinte héritée commence par $ : les deux formats seraient confondus")
	}
	if len(heritee) != 64 {
		t.Errorf("l'empreinte héritée fait %d caractères, attendu 64", len(heritee))
	}
	if n := strings.Count(moderne, "$"); n != 5 {
		t.Errorf("la chaîne PHC porte %d séparateurs, attendu 5 : %q", n, moderne)
	}
}

// TestUneEmpreinteIllisibleEstRefusee : fail-closed. Une valeur qu'on ne sait
// pas relire n'est pas devinée — elle est refusée.
func TestUneEmpreinteIllisibleEstRefusee(t *testing.T) {
	const sel = "00112233445566778899aabbccddeeff"
	cas := []struct {
		nom       string
		empreinte string
	}{
		{"vide", ""},
		{"texte quelconque", "pas une empreinte"},
		{"hexadécimal trop court", strings.Repeat("a", 63)},
		{"hexadécimal trop long", strings.Repeat("a", 65)},
		{"PHC tronquée", "$argon2id$v=19$m=19456,t=2,p=1$c2VsY2VsMTIzNDU2"},
		{"PHC sans paramètres", "$argon2id$v=19$$c2Vs$aGFzaA"},
		{"PHC base64 invalide", "$argon2id$v=19$m=19456,t=2,p=1$@@@@$aGFzaA"},
		{"PHC sel vide", "$argon2id$v=19$m=19456,t=2,p=1$$aGFzaA"},
		{"autre algorithme", "$argon2i$v=19$m=19456,t=2,p=1$c2Vs$aGFzaA"},
	}
	for _, c := range cas {
		if valide, _ := Verifier("n'importe quoi", sel, c.empreinte); valide {
			t.Errorf("%s : acceptée alors qu'elle est illisible", c.nom)
		}
	}
}

// TestUneVersionInconnueEstRefusee — construite pour que l'empreinte CORRESPONDE.
//
// Un cas où le condensat ne correspond de toute façon pas serait refusé même
// sans le contrôle de version : le test passerait au vert sur du code qui ne
// contrôle rien. On part donc d'une empreinte valide et on ne change QUE la
// version — le refus ne peut alors venir que du contrôle qu'on éprouve.
func TestUneVersionInconnueEstRefusee(t *testing.T) {
	bonne, _, _ := Hacher("mot de passe")
	truquee := strings.Replace(bonne, "$v=19$", "$v=99$", 1)
	if truquee == bonne {
		t.Fatal("la version n'a pas pu être remplacée : le test ne mesure rien")
	}

	if valide, _ := Verifier("mot de passe", "", truquee); valide {
		t.Error("une empreinte annonçant une version d'argon2 inconnue est acceptée")
	}
}

// TestDesParametresNulsSontRefuses — même précaution : l'empreinte correspond.
//
// Le contrôle n'est pas cosmétique. argon2.IDKey PANIQUE sur des paramètres
// nuls ; une ligne corrompue en base ferait donc tomber la goroutine
// d'authentification au lieu de refuser une connexion. Refuser avant l'appel
// transforme une panne en simple échec.
func TestDesParametresNulsSontRefuses(t *testing.T) {
	sel := []byte("selselselselsel1")
	cas := []struct {
		nom        string
		mem, tours uint32
		fils       uint8
	}{
		{"mémoire nulle", 0, ArgonTours, ArgonFils},
		{"zéro passe", ArgonMemoireKio, 0, ArgonFils},
		{"zéro fil", ArgonMemoireKio, ArgonTours, 0},
	}
	for _, c := range cas {
		empreinte := phc(c.mem, c.tours, c.fils, sel, "mot de passe")
		if valide, _ := Verifier("mot de passe", "", empreinte); valide {
			t.Errorf("%s : acceptée, alors qu'argon2 paniquerait sur ces paramètres", c.nom)
		}
	}
}

// TestUneEmpreinteAffaiblieEstSignalee : le jour où les paramètres montent, les
// empreintes calculées avec les anciens doivent être reprises.
func TestUneEmpreinteAffaiblieEstSignalee(t *testing.T) {
	sel := []byte("selselselselsel1")

	// Empreinte fabriquée avec des paramètres SOUS le réglage courant.
	faible := phc(ArgonMemoireKio/2, ArgonTours, ArgonFils, sel, "mot de passe")
	valide, aReencoder := Verifier("mot de passe", "", faible)
	if !valide {
		t.Fatal("une empreinte à paramètres plus faibles n'est plus relue : les comptes seraient bloqués")
	}
	if !aReencoder {
		t.Error("une empreinte à paramètres plus faibles n'est pas signalée")
	}
}

// TestUneEmpreintePlusForteNEstPasAffaiblie : le réencodage ne doit jamais
// RABAISSER une empreinte calculée plus fortement que le réglage du jour.
func TestUneEmpreintePlusForteNEstPasAffaiblie(t *testing.T) {
	sel := []byte("selselselselsel1")
	forte := phc(ArgonMemoireKio*2, ArgonTours+1, ArgonFils, sel, "mot de passe")

	valide, aReencoder := Verifier("mot de passe", "", forte)
	if !valide {
		t.Fatal("une empreinte plus forte est refusée")
	}
	if aReencoder {
		t.Error("une empreinte plus forte que le réglage courant serait réencodée, donc affaiblie")
	}
}

// TestLeSelHeriteNEstPasUtiliseParArgon2id : le sel d'argon2id est DANS la
// chaîne PHC. Passer un sel de colonne différent ne doit rien changer — sinon
// le réencodage, qui écrit un sel neuf dans les deux endroits, casserait toute
// empreinte relue avec l'ancien.
func TestLeSelHeriteNEstPasUtiliseParArgon2id(t *testing.T) {
	empreinte, _, _ := Hacher("mot de passe")

	if valide, _ := Verifier("mot de passe", "un sel sans rapport", empreinte); !valide {
		t.Error("la vérification argon2id dépend du sel de la colonne, elle ne devrait pas")
	}
}

// phc fabrique une empreinte avec des paramètres choisis, pour les tests.
func phc(memoire, tours uint32, fils uint8, sel []byte, motDePasse string) string {
	return construirePHC(motDePasse, sel, memoire, tours, fils)
}
