package action

import (
	"strings"
	"testing"
)

// Tests de la validation des clés publiques SSH.
//
// # Pourquoi ces contrôles comptent
//
// Une clé publique ajoutée à un compte permet de s'y connecter SANS mot de
// passe, sur toutes les machines du parc où ce compte est provisionné. Et
// l'opération ne laisse aucune trace visible pour son titulaire, qui n'a pas de
// raison d'aller inspecter la liste de ses clés.
//
// # Pourquoi la fonction est exportée
//
// La page /profil n'emprunte pas le registre, et ne le peut pas : modifier son
// propre profil ne doit pas exiger « write:update:user », qui est le droit
// d'agir sur le compte d'autrui. Elle avait donc sa propre copie de ces
// contrôles — et la copie était plus faible. C'est le genre d'écart qu'une
// définition unique supprime définitivement.

func TestValiderCleSSHAccepteLesSeptTypes(t *testing.T) {
	corps := "AAAAB3NzaC1yc2EAAAADAQABAAABgQC"

	for _, typ := range typesDeClesAcceptes {
		if err := ValiderCleSSH(typ + " " + corps + " commentaire"); err != nil {
			t.Errorf("type %q refusé : %v", typ, err)
		}
	}

	// Sept, et pas deux. La page /profil n'en acceptait que deux — ssh-rsa et
	// ssh-ed25519 — si bien qu'une clé ECDSA ou une clé matérielle était refusée
	// sur le portail et acceptée en ligne de commande, sans que le message dise
	// pourquoi.
	if len(typesDeClesAcceptes) < 7 {
		t.Errorf("%d types acceptés : la liste a rétréci", len(typesDeClesAcceptes))
	}
}

// TestValiderCleSSHRefuseLeSautDeLigne.
//
// Chaque ligne d'authorized_keys est une clé DISTINCTE. Un fichier de deux
// lignes déposé sur la page profil ajoutait donc deux entrées pour une seule
// visible dans la liste des clés — et la seconde ne se serait jamais retirée par
// l'interface, puisque rien ne l'y affichait.
func TestValiderCleSSHRefuseLeSautDeLigne(t *testing.T) {
	corps := "AAAAB3NzaC1yc2EAAAADAQABAAABgQC"

	for _, cas := range []string{
		"ssh-rsa " + corps + "\nssh-rsa " + corps + " intruse",
		"ssh-rsa " + corps + "\r\nssh-ed25519 " + corps,
	} {
		err := ValiderCleSSH(cas)
		if err == nil {
			t.Fatalf("clé sur plusieurs lignes acceptée (%q) : une seconde entrée serait "+
				"ajoutée à authorized_keys sans jamais apparaître dans la liste des clés", cas)
		}
		if !strings.Contains(err.Error(), "saut de ligne") {
			t.Errorf("message %q : ne dit pas ce qui cloche", err.Error())
		}
	}
}

// TestValiderCleSSHRefuseUnPrefixeTrompeur.
//
// Le contrôle porte sur le PREMIER CHAMP et non sur un HasPrefix de la chaîne
// entière : « ssh-rsaXXXX … » commence bien par « ssh-rsa » sans être une clé
// valide, et passerait un contrôle naïf — celui qu'avait la page /profil.
func TestValiderCleSSHRefuseUnPrefixeTrompeur(t *testing.T) {
	if err := ValiderCleSSH("ssh-rsaXXXX AAAAB3NzaC1yc2E"); err == nil {
		t.Error("« ssh-rsaXXXX » accepté : le contrôle porte sur le préfixe et non sur le champ")
	}
}

func TestValiderCleSSHRefuseCeQuiNEstPasUneCle(t *testing.T) {
	cas := []struct{ nom, valeur string }{
		{"vide", ""},
		{"espaces", "   "},
		{"un seul champ", "ssh-rsa"},
		{"type inconnu", "ssh-dss AAAAB3NzaC1kc3MAAACB"},
		{"pas une clé", "bonjour tout le monde"},
		{"clé privée", "-----BEGIN OPENSSH PRIVATE KEY-----"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if err := ValiderCleSSH(c.valeur); err == nil {
				t.Errorf("%q accepté comme clé publique", c.valeur)
			}
		})
	}
}

// TestSshDssResteRefuse.
//
// Refusé délibérément, et non par oubli : OpenSSH désactive DSA par défaut
// depuis la version 7.0. La clé serait acceptée ici pour être ensuite ignorée
// par le serveur SSH — un échec de connexion sans cause visible, donc le pire
// des deux comportements.
func TestSshDssResteRefuse(t *testing.T) {
	for _, typ := range typesDeClesAcceptes {
		if typ == "ssh-dss" {
			t.Fatal("ssh-dss a été ajouté aux types acceptés : la clé serait " +
				"enregistrée puis ignorée par OpenSSH, sans message")
		}
	}
}

// TestMessageDeRefusNommeLesTypesAcceptes.
//
// « type non reconnu » oblige à chercher la liste dans le code. La donner évite
// d'avoir à générer une seconde clé au hasard pour trouver laquelle passe.
func TestMessageDeRefusNommeLesTypesAcceptes(t *testing.T) {
	err := ValiderCleSSH("ssh-dss AAAAB3NzaC1kc3MAAACB")
	if err == nil {
		t.Fatal("ssh-dss accepté")
	}
	for _, attendu := range []string{"ssh-ed25519", "ecdsa-sha2-nistp256"} {
		if !strings.Contains(err.Error(), attendu) {
			t.Errorf("message %q : ne nomme pas %q parmi les types acceptés", err.Error(), attendu)
		}
	}
}

// TestAjoutExigeUnLibelle.
//
// Le libellé est ce qui permettra de retirer la clé plus tard. Sans lui, la
// liste affiche des lignes indistinctes et le retrait devient un pari sur un
// identifiant.
func TestAjoutExigeUnLibelle(t *testing.T) {
	_, err := ajouterCleUtilisateur(Appelant{}, Params{
		"username": "bob",
		"key":      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI",
	})
	if err == nil {
		t.Fatal("clé acceptée sans libellé")
	}
	if !strings.Contains(err.Error(), "ibellé") {
		t.Errorf("message %q : ne désigne pas ce qui manque", err.Error())
	}
}

// TestRetraitExigeLUtilisateurEtLIdentifiant.
//
// La cible ne se déduit pas de l'identifiant de clé : c'est justement ce que le
// contrôle d'appartenance vérifie ensuite, et sans nom d'utilisateur il n'aurait
// rien à quoi comparer.
func TestRetraitExigeLUtilisateurEtLIdentifiant(t *testing.T) {
	if _, err := retirerCleUtilisateur(Appelant{}, Params{"key_id": "3"}); err == nil {
		t.Error("retrait accepté sans utilisateur cible")
	}
	if _, err := retirerCleUtilisateur(Appelant{}, Params{"username": "bob"}); err == nil {
		t.Error("retrait accepté sans identifiant de clé")
	}
	for _, v := range []string{"abc", "0", "-1", "1.5"} {
		if _, err := retirerCleUtilisateur(Appelant{}, Params{"username": "bob", "key_id": v}); err == nil {
			t.Errorf("identifiant de clé %q accepté", v)
		}
	}
}
