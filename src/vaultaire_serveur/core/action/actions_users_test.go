package action

import (
	"encoding/hex"
	"strings"
	"testing"

	"vaultaire/core/global/security"
)

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

// TestFormeDuSelEtDuHache : la forme attendue par la base ET par la relecture.
//
// # Ce test décrivait l'ancien schéma
//
// Il exigeait un haché de 32 octets hexadécimaux — SHA-256(sel‖mot de passe),
// que le client recalculait de son côté. Le stockage est passé à argon2id
// (`core/global/security`) : l'empreinte est une chaîne PHC qui porte ses
// propres paramètres, et c'est le CORE qui vérifie, le mot de passe transitant
// dans le tunnel depuis le point 29.
//
// Le test n'avait pas suivi et échouait à chaque exécution. Un test rouge en
// permanence ne surveille plus rien : on cesse de le lire, et le vrai échec du
// jour se perd dans le bruit. Il décrit donc désormais le contrat réel.
func TestFormeDuSelEtDuHache(t *testing.T) {
	sel, empreinte, err := hacherMotDePasse("motdepasse")
	if err != nil {
		t.Fatalf("hachage : %v", err)
	}

	// Le sel reste écrit en hexadécimal dans la colonne `salt`, NOT NULL et
	// encore lue pour les comptes hérités.
	selBrut, err := hex.DecodeString(sel)
	if err != nil {
		t.Fatalf("le sel n'est pas de l'hexadécimal : %v", err)
	}
	if len(selBrut) != security.ArgonSelOctets {
		t.Fatalf("sel de %d octets, attendu %d", len(selBrut), security.ArgonSelOctets)
	}

	if !strings.HasPrefix(empreinte, "$argon2id$") {
		t.Fatalf("empreinte %q : attendu une chaîne PHC argon2id — "+
			"une empreinte sans ses paramètres ne serait plus relisible le jour où ils changent", empreinte)
	}
	if champs := strings.Split(empreinte, "$"); len(champs) != 6 {
		t.Fatalf("empreinte %q : %d champs, attendu 6 ($argon2id$v=…$m=…,t=…,p=…$sel$somme)",
			empreinte, len(champs))
	}
}

// TestLEmpreinteSeRelitParVerifier : le haché produit ici est celui que les
// quatre portes (web, LDAP, Ducky, PAM) relisent.
//
// C'est ce qui remplace l'ancien contrôle de l'ordre « sel‖mot de passe » :
// cette règle appartenait au schéma SHA-256, où le client refaisait le calcul.
// Ce qui compte aujourd'hui est qu'une empreinte fraîche soit acceptée par
// `security.Verifier` — et n'exige AUCUN réencodage, sans quoi chaque connexion
// réécrirait la base pour rien.
func TestLEmpreinteSeRelitParVerifier(t *testing.T) {
	sel, empreinte, err := hacherMotDePasse("secret")
	if err != nil {
		t.Fatalf("hachage : %v", err)
	}

	ok, aReencoder := security.Verifier("secret", sel, empreinte)
	if !ok {
		t.Fatal("le mot de passe juste haché est refusé : le stockage et la vérification divergent")
	}
	if aReencoder {
		t.Error("une empreinte fraîche est déclarée à réencoder : chaque connexion réécrirait la base")
	}

	if ok, _ := security.Verifier("mauvais", sel, empreinte); ok {
		t.Fatal("un mot de passe faux est accepté")
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
