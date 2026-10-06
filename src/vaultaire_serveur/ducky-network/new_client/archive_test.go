package newclient

import (
	"strings"
	"testing"

	autoaddclientgo "vaultaire/ducky-network/new_client/AUTO_ADD_client.go"

	duckykey "vaultaire/ducky-network/key_management"
)

// Ces tests ne demandent PAS de base de données.
//
// Ce qui en demanderait — le refus d'un client service, la lecture de
// l'identité — est éprouvé en recette (A_TESTER). Ce qui est vérifié ici est
// exactement ce qui se trompe en SILENCE : la composition de l'archive. Un
// fichier oublié ne fait échouer aucune fabrication ; il produit un agent
// dégradé que l'on découvre des semaines plus tard, sur un poste, sans rien
// pour relier la panne à la cause.

func TestLArchiveWindowsNePorteJamaisLaClePolitique(t *testing.T) {
	fichiers := strings.Join(fichiersDeLArchive(SystemeWindows), " ")

	// L'agent Windows ignore les trames de politique : cette clé n'aurait aucun
	// lecteur, et un fichier dont personne ne sait dire l'usage est un fichier
	// qu'on finit par recopier ailleurs « au cas où ».
	if strings.Contains(fichiers, duckykey.GPOPublicKeyFileName) {
		t.Errorf("l'archive Windows porte %s : %s", duckykey.GPOPublicKeyFileName, fichiers)
	}
}

func TestLArchiveLinuxPorteToutCeQueLAgentAttend(t *testing.T) {
	fichiers := fichiersDeLArchive(SystemeLinux)
	index := map[string]bool{}
	for _, f := range fichiers {
		index[f] = true
	}

	for _, attendu := range []string{
		"client_software.yaml",           // l'identité
		"private_key.pem",                // la clé privée de la machine
		duckykey.CoreFingerprintFileName, // de quoi attester la clé du core
		autoaddclientgo.NomConfClient,    // les cores à joindre
		duckykey.GPOPublicKeyFileName,    // la signature des politiques
	} {
		if !index[attendu] {
			t.Errorf("%s manque à l'archive Linux : %v", attendu, fichiers)
		}
	}
}

// Les deux fichiers d'IDENTITÉ sont dans toutes les archives.
//
// Ce sont les seuls qui ne soient pas reconstructibles : la clé privée n'existe
// que dans ce fichier, la base ne porte que la publique. Les oublier produirait
// une archive qui s'ouvre, qui a l'air complète, et qui n'installe rien.
func TestLIdentiteEstDansToutesLesArchives(t *testing.T) {
	for _, systeme := range []string{SystemeLinux, SystemeWindows} {
		fichiers := strings.Join(fichiersDeLArchive(systeme), " ")
		for _, attendu := range []string{"client_software.yaml", "private_key.pem"} {
			if !strings.Contains(fichiers, attendu) {
				t.Errorf("%s : %s manque (%s)", systeme, attendu, fichiers)
			}
		}
	}
}

func TestLeSystemeParDefautEstLinux(t *testing.T) {
	// Par défaut vers l'archive la PLUS complète : un fichier inutile sur un
	// poste se voit et ne coûte rien ; un fichier manquant donne un agent qui
	// fonctionne en apparence et ne vérifie plus les signatures.
	for _, saisi := range []string{"", "  ", "LINUX", "Linux"} {
		got, err := SystemeValide(saisi)
		if err != nil || got != SystemeLinux {
			t.Errorf("SystemeValide(%q) = %q, %v ; attendu %q", saisi, got, err, SystemeLinux)
		}
	}
	if got, err := SystemeValide("Windows"); err != nil || got != SystemeWindows {
		t.Errorf("SystemeValide(\"Windows\") = %q, %v", got, err)
	}
}

func TestUnSystemeInconnuEstRefuseEtNonRabattu(t *testing.T) {
	// Refusé, et non rabattu sur Linux : « --os win » doit se corriger, pas
	// produire silencieusement une archive qui porte un fichier de trop et un
	// mode d'emploi qui parle du mauvais système.
	if _, err := SystemeValide("win"); err == nil {
		t.Fatal("« win » a ete accepte")
	} else if !strings.Contains(err.Error(), "linux") || !strings.Contains(err.Error(), "windows") {
		t.Errorf("le refus ne nomme pas les valeurs attendues : %v", err)
	}
}

// Le lisez-moi doit AVERTIR, pas seulement décrire.
func TestLeLisezMoiAvertitDeLaClePrivee(t *testing.T) {
	texte := texteLisezMoi("ABC123-30-09-2026", SystemeWindows, nil)

	if !strings.Contains(texte, "CLE PRIVEE") {
		t.Error("le lisez-moi ne dit pas que l'archive contient une cle privee")
	}
	if !strings.Contains(texte, "ABC123-30-09-2026") {
		t.Error("le lisez-moi ne nomme pas la machine")
	}
	// Le mode d'emploi doit être celui du système demandé, sinon il envoie
	// déposer des fichiers dans un répertoire qui n'existe pas sur ce poste.
	if !strings.Contains(texte, "install.ps1") {
		t.Error("le lisez-moi Windows ne parle pas d'install.ps1")
	}
	if strings.Contains(texte, "/etc/vaultaire_client") {
		t.Error("le lisez-moi Windows parle de chemins Linux")
	}
}

// Un compagnon manquant doit se lire DANS l'archive.
//
// C'est le seul endroit où celui qui l'ouvre — des jours plus tard, sur une
// autre machine, sans le journal du core sous les yeux — peut apprendre que son
// agent démarrera en mode dégradé, et lequel.
func TestLeLisezMoiNommeLesFichiersManquants(t *testing.T) {
	texte := texteLisezMoi("ABC", SystemeLinux, []string{duckykey.CoreFingerprintFileName})

	if !strings.Contains(texte, "ATTENTION") {
		t.Error("l'avertissement n'apparait pas")
	}
	if !strings.Contains(texte, duckykey.CoreFingerprintFileName) {
		t.Error("le fichier manquant n'est pas nomme")
	}
	// Et il doit dire ce que cela COÛTE, pas seulement ce qui manque : « il
	// manque un fichier » n'aide personne à décider s'il faut recommencer.
	if !strings.Contains(texte, "premiere cle") {
		t.Error("la consequence du manque n'est pas expliquee")
	}

	// Sans manque, pas d'avertissement : un bandeau permanent qu'on apprend à
	// ignorer ne protège plus le jour où il dit quelque chose.
	if strings.Contains(texteLisezMoi("ABC", SystemeLinux, nil), "ATTENTION") {
		t.Error("l'avertissement apparait alors que rien ne manque")
	}
}
