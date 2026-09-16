package localusermanagement

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Tests de la carte d'UID.
//
// # Ce qu'ils protègent
//
// Le défaut d'origine — un UID unique partagé par tous les utilisateurs du
// domaine — ne produisait aucune erreur. Tout fonctionnait : les connexions
// aboutissaient, les fichiers s'écrivaient. Simplement, alice et bob étaient le
// même utilisateur pour le noyau.
//
// C'est le profil de défaut qu'aucun test d'intégration ne rattrape : il faut
// une assertion explicite sur l'unicité.

func cartePourTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("VAULTAIRE_UID_MAP_DIR", dir)
	return filepath.Join(dir, "uid.map")
}

// TestChaqueUtilisateurAUnUIDDistinct est LE test de non-régression.
func TestChaqueUtilisateurAUnUIDDistinct(t *testing.T) {
	cartePourTest(t)

	noms := []string{"alice@dom", "bob@dom", "carol@dom", "dave@dom", "eve@dom"}
	vus := map[int]string{}

	for _, nom := range noms {
		e, err := EnsureUIDMapping(nom)
		if err != nil {
			t.Fatalf("attribution impossible pour %s : %v", nom, err)
		}
		if precedent, collision := vus[e.UID]; collision {
			t.Fatalf("UID %d attribué à la fois à %s et à %s — aucune séparation entre les deux comptes",
				e.UID, precedent, nom)
		}
		vus[e.UID] = nom
	}

	if len(vus) != len(noms) {
		t.Errorf("%d UID distincts pour %d utilisateurs", len(vus), len(noms))
	}
}

// TestUIDStableEntreDeuxAppels : l'identité ne doit pas bouger.
//
// Un UID qui changerait entre deux connexions laisserait derrière lui des
// fichiers appartenant à un numéro que plus personne ne porte — et qui serait
// réattribué à quelqu'un d'autre, lequel en hériterait.
func TestUIDStableEntreDeuxAppels(t *testing.T) {
	cartePourTest(t)

	premier, err := EnsureUIDMapping("alice@dom")
	if err != nil {
		t.Fatalf("première attribution : %v", err)
	}
	// Un autre utilisateur passe entre les deux : l'UID d'alice ne doit pas en
	// être affecté.
	if _, err := EnsureUIDMapping("bob@dom"); err != nil {
		t.Fatalf("attribution intermédiaire : %v", err)
	}
	second, err := EnsureUIDMapping("alice@dom")
	if err != nil {
		t.Fatalf("seconde attribution : %v", err)
	}

	if premier.UID != second.UID {
		t.Errorf("l'UID d'alice a changé : %d puis %d", premier.UID, second.UID)
	}
}

// TestAttributionConcurrente : deux provisionnements simultanés ne doivent pas
// se marcher dessus.
//
// C'est ce que faisait getNextAvailableUID, qui relisait /etc/passwd sans
// verrou : deux goroutines y trouvaient le même trou et attribuaient le même
// UID. À lancer avec -race.
func TestAttributionConcurrente(t *testing.T) {
	cartePourTest(t)

	const n = 12
	var wg sync.WaitGroup
	resultats := make([]UIDEntry, n)
	erreurs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resultats[i], erreurs[i] = EnsureUIDMapping(nomIndex(i))
		}(i)
	}
	wg.Wait()

	vus := map[int]string{}
	for i := 0; i < n; i++ {
		if erreurs[i] != nil {
			t.Fatalf("attribution %d : %v", i, erreurs[i])
		}
		if precedent, collision := vus[resultats[i].UID]; collision {
			t.Fatalf("UID %d attribué deux fois (%s et %s) sous concurrence",
				resultats[i].UID, precedent, resultats[i].Username)
		}
		vus[resultats[i].UID] = resultats[i].Username
	}
}

func nomIndex(i int) string {
	return string(rune('a'+i)) + "user@dom"
}

// TestUIDDansLaPlage : jamais 0, jamais hors bornes.
//
// Le module NSS refuse ce qui sort de la plage ; produire de telles entrées les
// rendrait simplement invisibles, donc l'utilisateur inconnu — un échec
// silencieux plutôt qu'une erreur.
func TestUIDDansLaPlage(t *testing.T) {
	cartePourTest(t)

	e, err := EnsureUIDMapping("alice@dom")
	if err != nil {
		t.Fatalf("attribution : %v", err)
	}
	if e.UID < UIDMin || e.UID > UIDMax {
		t.Errorf("UID %d hors de la plage %d-%d", e.UID, UIDMin, UIDMax)
	}
	if e.UID == 0 || e.GID == 0 {
		t.Error("UID ou GID nul : ce serait root")
	}
}

// TestCarteRelisible : ce qui est écrit doit se relire à l'identique.
func TestCarteRelisible(t *testing.T) {
	chemin := cartePourTest(t)

	attendus := map[string]int{}
	for _, nom := range []string{"alice@dom", "bob@dom", "carol@dom"} {
		e, err := EnsureUIDMapping(nom)
		if err != nil {
			t.Fatalf("attribution : %v", err)
		}
		attendus[nom] = e.UID
	}

	relu, err := LoadUIDMap()
	if err != nil {
		t.Fatalf("relecture : %v", err)
	}
	for nom, uid := range attendus {
		if relu[nom].UID != uid {
			t.Errorf("%s : écrit %d, relu %d", nom, uid, relu[nom].UID)
		}
	}

	// Le fichier doit être lisible par tous : NSS est chargé dans des processus
	// non privilégiés. En 0600, la résolution échouerait pour tout le monde sauf
	// root — donc pour sshd avant qu'il ne change d'identité, mais pas pour
	// « ls -l » lancé par l'utilisateur.
	info, err := os.Stat(chemin)
	if err != nil {
		t.Fatalf("stat : %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode %o, attendu 644 — NSS doit pouvoir lire sans privilège", info.Mode().Perm())
	}
}

// TestLignesInvalidesIgnorees : une carte abîmée ne doit pas tout perdre.
//
// Et surtout : une ligne hors plage ne doit pas entrer. Si quoi que ce soit
// permettait d'écrire dans la carte, « attaquant@dom:0:0 » ferait de ce compte
// root aux yeux de la libc.
func TestLignesInvalidesIgnorees(t *testing.T) {
	chemin := cartePourTest(t)

	contenu := strings.Join([]string{
		"# commentaire",
		"",
		"valide@dom:5100:5100",
		"pirate@dom:0:0",            // root : doit être refusé
		"horsplage@dom:99999:99999", // au-delà de UIDMax
		"malforme@dom:pasunnombre:5101",
		"troppeu@dom:5102",
		"suivant@dom:5103:5103",
	}, "\n") + "\n"

	if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
		t.Fatalf("écriture : %v", err)
	}

	entries, err := LoadUIDMap()
	if err != nil {
		t.Fatalf("lecture : %v", err)
	}

	for _, refuse := range []string{"pirate@dom", "horsplage@dom", "malforme@dom", "troppeu@dom"} {
		if _, present := entries[refuse]; present {
			t.Errorf("l'entrée invalide %q a été acceptée", refuse)
		}
	}
	for _, accepte := range []string{"valide@dom", "suivant@dom"} {
		if _, present := entries[accepte]; !present {
			t.Errorf("l'entrée valide %q a été perdue à cause d'une ligne voisine", accepte)
		}
	}
}

// TestRetraitDeCarte vérifie la suppression.
func TestRetraitDeCarte(t *testing.T) {
	cartePourTest(t)

	if _, err := EnsureUIDMapping("alice@dom"); err != nil {
		t.Fatalf("attribution : %v", err)
	}
	if _, err := EnsureUIDMapping("bob@dom"); err != nil {
		t.Fatalf("attribution : %v", err)
	}

	if err := RemoveUIDMapping("alice@dom"); err != nil {
		t.Fatalf("retrait : %v", err)
	}

	entries, err := LoadUIDMap()
	if err != nil {
		t.Fatalf("lecture : %v", err)
	}
	if _, present := entries["alice@dom"]; present {
		t.Error("alice est encore dans la carte après retrait")
	}
	if _, present := entries["bob@dom"]; !present {
		t.Error("bob a disparu alors que seul alice était visé")
	}

	// Retirer un absent n'est pas une erreur : la suppression doit être
	// rejouable sans condition.
	if err := RemoveUIDMapping("inexistant@dom"); err != nil {
		t.Errorf("le retrait d'un absent a échoué : %v", err)
	}
}

// TestAdopteLUIDDuCompteLocal : la carte doit se conformer à /etc/passwd.
//
// # Le défaut constaté en production
//
// Un compte provisionné AVANT l'existence de la carte se voyait attribuer un
// second numéro : /etc/passwd disait 5000, la carte 5001.
//
//	point 6 (service) : admin@vaultaire.fr:5001:5001
//	point 7 (getent)  : admin@vaultaire.fr:x:5000:5000
//
// La divergence est silencieuse — « files » venant en premier dans
// nsswitch.conf, c'est l'UID de /etc/passwd qui fait autorité et tout
// fonctionne. Mais la carte ment sur la seule chose qu'elle est censée savoir.
// Le jour où le compte local est purgé puis recréé, ou l'ordre de nsswitch.conf
// modifié, l'utilisateur change d'identité et perd ses fichiers.
//
// Ce test utilise le VRAI /etc/passwd de la machine : on cherche un compte qui
// s'y trouve déjà, et on vérifie que la carte adopte son UID plutôt que d'en
// inventer un.
func TestAdopteLUIDDuCompteLocal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VAULTAIRE_UID_MAP_DIR", dir)

	// Un /etc/passwd fabriqué : le test ne dépend plus de la machine qui
	// l'exécute, et mesure donc quelque chose partout.
	passwd := filepath.Join(dir, "passwd")
	contenu := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"admin@vaultaire.fr:x:5000:5000:admin:/home/admin@vaultaire.fr:/bin/bash",
	}, "\n") + "\n"
	if err := os.WriteFile(passwd, []byte(contenu), 0o644); err != nil {
		t.Fatalf("écriture : %v", err)
	}
	t.Setenv("VAULTAIRE_PASSWD_FILE", passwd)

	e, err := EnsureUIDMapping("admin@vaultaire.fr")
	if err != nil {
		t.Fatalf("attribution : %v", err)
	}
	if e.UID != 5000 {
		t.Fatalf("la carte attribue %d alors que /etc/passwd dit 5000 : "+
			"les deux sources divergent, et le jour où le compte local est recréé "+
			"ou l'ordre de nsswitch.conf modifié, l'utilisateur change d'identité "+
			"et perd ses fichiers", e.UID)
	}

	// Et un utilisateur SANS compte local reçoit bien un numéro neuf, qui
	// n'entre pas en collision avec celui déjà pris.
	autre, err := EnsureUIDMapping("nouveau@vaultaire.fr")
	if err != nil {
		t.Fatalf("attribution : %v", err)
	}
	if autre.UID == 5000 {
		t.Error("collision avec l'UID d'un compte local existant")
	}
}

// TestNAdoptePasUnUIDHorsPlage : un compte système ne doit pas entrer.
//
// root porte l'UID 0. L'adopter mettrait « 0 » dans la carte — que le module NSS
// refuserait, mais qui n'a rien à y faire.
func TestNAdoptePasUnUIDHorsPlage(t *testing.T) {
	cartePourTest(t)

	if _, _, trouve := uidDuCompteLocal("root"); trouve {
		t.Error("root a été retenu comme candidat à l'adoption")
	}
}
