package action

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// sha256Hex reproduit le calcul attendu, indépendamment du code testé.
//
// Écrit ici plutôt que réutilisé depuis la source : un test qui appellerait la
// fonction qu'il vérifie ne comparerait rien. Il faut une seconde expression de
// la même règle pour que la comparaison ait un sens.
func sha256Hex(donnees []byte) string {
	somme := sha256.Sum256(donnees)
	return hex.EncodeToString(somme[:])
}

// Tests des règles portées depuis les deux anciennes versions.
//
// Ils ne touchent pas la base : ce qui est vérifié ici est précisément ce qui
// DIVERGEAIT entre la ligne de commande et le web — la déduction du prénom, le
// hachage, les noms réservés. Le reste de l'action n'est qu'un appel à la
// couche de persistance.
//
// C'est aussi ce qui rend ces tests possibles. Tant que la règle vivait au
// milieu d'un handler HTTP de mille lignes, la tester demandait un serveur et
// une base — donc personne ne l'a fait, et les deux versions ont pu diverger
// pendant des mois sans que rien ne le signale.

// TestDeductionPrenomNom : règle venue de la ligne de commande.
//
// Le web ne la portait pas : il recopiait l'identifiant complet dans les deux
// champs. Un compte créé depuis le web s'appelait donc « jean.dupont
// jean.dupont » dans l'annuaire.
func TestDeductionPrenomNom(t *testing.T) {
	cas := []struct {
		identifiant string
		prenom      string
		nom         string
	}{
		{"jean.dupont", "jean", "dupont"},
		{"alice", "alice", "alice"},

		// Deux points : SplitN à 2 garde « pierre.dupont » comme nom. Un Split
		// simple aurait rendu trois morceaux et perdu le dernier en silence —
		// le nom de famille amputé, sans erreur.
		{"jean.pierre.dupont", "jean", "pierre.dupont"},

		// Points mal placés : mieux vaut ne rien déduire qu'un prénom vide.
		{".dupont", ".dupont", ".dupont"},
		{"jean.", "jean.", "jean."},
	}

	for _, c := range cas {
		t.Run(c.identifiant, func(t *testing.T) {
			prenom, nom := deduireIdentite(c.identifiant)
			if prenom != c.prenom || nom != c.nom {
				t.Fatalf("%q → (%q, %q), attendu (%q, %q)",
					c.identifiant, prenom, nom, c.prenom, c.nom)
			}
		})
	}
}

// TestNomsReservesInsensiblesALaCasse.
//
// Les deux anciennes versions comparaient déjà en minuscules, mais seulement
// pour « vaultaire ». « root » ne figurait nulle part, alors que c'est le compte
// que la création d'un homonyme perturberait le plus sur les machines clientes.
func TestNomsReservesInsensiblesALaCasse(t *testing.T) {
	for _, nom := range []string{"vaultaire", "Vaultaire", "VAULTAIRE", "root", "Root"} {
		if !nomsReserves[strings.ToLower(nom)] {
			t.Errorf("%q n'est pas reconnu comme réservé : un compte homonyme du compte "+
				"de service pourrait être créé", nom)
		}
	}
	if nomsReserves["alice"] {
		t.Error("un nom ordinaire est traité comme réservé")
	}
}

// TestHachageSelAleatoire : deux comptes, même mot de passe, hachés différents.
//
// C'est ce que le sel apporte, et c'est vérifiable sans base. Un sel constant —
// ou oublié — donnerait deux hachés identiques, et une seule table précalculée
// ouvrirait les deux comptes.
func TestHachageSelAleatoire(t *testing.T) {
	sel1, hache1, err := hacherMotDePasse("le meme mot de passe")
	if err != nil {
		t.Fatalf("hachage : %v", err)
	}
	sel2, hache2, err := hacherMotDePasse("le meme mot de passe")
	if err != nil {
		t.Fatalf("hachage : %v", err)
	}

	if sel1 == sel2 {
		t.Fatal("deux sels identiques : le sel n'est pas tiré au hasard")
	}
	if hache1 == hache2 {
		t.Fatal("deux hachés identiques pour le même mot de passe : le sel n'entre pas dans le calcul")
	}
}

// TestFormeDuSelEtDuHache : longueurs attendues par la base et par le client.
//
// Le client recalcule HMAC(SHA256(sel‖mot de passe)) à partir du sel reçu ; une
// longueur inattendue casserait l'authentification par mot de passe du réseau
// Ducky, et l'erreur n'apparaîtrait qu'à la première connexion d'un nouveau
// compte.
func TestFormeDuSelEtDuHache(t *testing.T) {
	sel, hache, err := hacherMotDePasse("motdepasse")
	if err != nil {
		t.Fatalf("hachage : %v", err)
	}

	selBrut, err := hex.DecodeString(sel)
	if err != nil {
		t.Fatalf("le sel n'est pas de l'hexadécimal : %v", err)
	}
	if len(selBrut) != 16 {
		t.Fatalf("sel de %d octets, attendu 16", len(selBrut))
	}

	hacheBrut, err := hex.DecodeString(hache)
	if err != nil {
		t.Fatalf("le haché n'est pas de l'hexadécimal : %v", err)
	}
	if len(hacheBrut) != 32 {
		t.Fatalf("haché de %d octets, attendu 32 (SHA-256)", len(hacheBrut))
	}
}

// TestHachageNeModifiePasLeMotDePasse vérifie l'ordre sel‖mot de passe.
//
// L'ordre compte : le client calcule SHA256(sel puis mot de passe). L'inverser
// ici produirait un haché que le client ne retrouverait jamais, et l'échec
// n'apparaîtrait qu'à la connexion — loin d'ici.
func TestHachageOrdreSelPuisMotDePasse(t *testing.T) {
	sel, hache, err := hacherMotDePasse("secret")
	if err != nil {
		t.Fatalf("hachage : %v", err)
	}

	selBrut, _ := hex.DecodeString(sel)
	attendu := sha256Hex(append(append([]byte{}, selBrut...), []byte("secret")...))
	if hache != attendu {
		t.Fatalf("haché %s, attendu %s — l'ordre sel‖mot de passe n'est pas respecté, "+
			"le client ne retrouverait jamais cette valeur", hache, attendu)
	}
}

// TestActionsUtilisateurToutesEnregistrees : l'inventaire et ses clés.
//
// Ce test est le garde-fou du fail-closed appliqué au lot : si quelqu'un ajoute
// une action utilisateur sans clé RBAC, MustEnregistrer panique et ce test
// échoue avec elle.
func TestActionsUtilisateurToutesEnregistrees(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsUtilisateur(r)

	attendues := map[string]string{
		"user.create":          "write:create:user",
		"user.update":          "write:update:user",
		"user.change_password": "write:update:user",
	}

	defs := r.Definitions()
	if len(defs) != len(attendues) {
		t.Fatalf("%d actions enregistrées, attendu %d", len(defs), len(attendues))
	}
	for _, d := range defs {
		cle, connue := attendues[d.Nom]
		if !connue {
			t.Errorf("action inattendue : %q", d.Nom)
			continue
		}
		if d.CleRBAC != cle {
			t.Errorf("action %q : clé %q, attendu %q", d.Nom, d.CleRBAC, cle)
		}
		if d.Portee == nil {
			t.Errorf("action %q sans portée", d.Nom)
		}
		if d.Resume == "" {
			t.Errorf("action %q sans résumé : elle n'apparaîtrait dans aucune aide", d.Nom)
		}
	}
}

// TestCreationExigeLeDroitGlobal.
//
// La création est la seule action utilisateur à portée globale, et il faut que
// ce soit délibéré : la cible n'existe pas encore, elle n'a donc aucun domaine
// dont déduire une portée. Rendre une liste vide aurait fait autoriser tout le
// monde — c'est le piège que domainesOuGlobal ferme.
func TestCreationExigeLeDroitGlobal(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsUtilisateur(r)

	d, ok := r.Definition("user.create")
	if !ok {
		t.Fatal("user.create absente du registre")
	}
	domaines, err := d.Portee(Params{"username": "alice"})
	if err != nil {
		t.Fatalf("portée : %v", err)
	}
	if len(domaines) != 1 || domaines[0] != "*" {
		t.Fatalf("portée %v, attendu [*] — un délégué d'un seul domaine pourrait "+
			"créer des comptes hors de son périmètre", domaines)
	}
}
