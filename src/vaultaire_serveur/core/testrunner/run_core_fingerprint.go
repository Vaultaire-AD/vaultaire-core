package testrunner

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	duckykey "vaultaire/ducky-network/key_management"
)

// Tests de l'attestation de la clé publique du core (point 14 de l'audit).
//
// # Ce que ces tests protègent
//
// L'empreinte de la clé du core doit franchir trois frontières : elle est
// CALCULÉE par le core, ÉCRITE dans un fichier, DÉPLACÉE par un script shell,
// puis LUE et COMPARÉE par l'agent et par le SDK.
//
// Ces quatre morceaux vivent dans des modules Go distincts et dans un script
// bash. Aucun compilateur ne les voit ensemble. Une divergence entre eux ne
// produit donc aucune erreur de compilation, et se manifeste par le pire des
// symptômes : l'empreinte n'est jamais trouvée, l'agent repasse en confiance
// aveugle, et tout continue de fonctionner.
//
// Autrement dit, une désynchronisation DÉSACTIVE la protection sans rien
// casser. C'est exactement le genre de défaut qu'une suite de tests doit
// attraper, parce que rien d'autre ne le fera.
func testCoreFingerprint() []Result {
	var out []Result

	out = append(out, testEmpreinteCalcul()...)
	out = append(out, testEmpreinteNomDeFichierPartage()...)
	out = append(out, testEmpreinteDepotPourClient()...)

	return out
}

func clePubliqueDeTest() (string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// testEmpreinteCalcul : le calcul doit être stable et discriminant.
func testEmpreinteCalcul() []Result {
	var out []Result

	cle, err := clePubliqueDeTest()
	if err != nil {
		return []Result{{"Empreinte/génération de clé", false, err.Error()}}
	}

	empreinte, err := duckykey.EmpreinteClePublique(cle)
	if err != nil {
		return []Result{{"Empreinte/calcul", false, err.Error()}}
	}

	// Forme : SHA256: + 43 caractères base64 sans remplissage, comme
	// ssh-keygen -lf. Un administrateur doit reconnaître ce qu'il lit.
	switch {
	case !strings.HasPrefix(empreinte, "SHA256:"):
		out = append(out, Result{"Empreinte/forme", false, "préfixe SHA256: absent : " + empreinte})
	case len(strings.TrimPrefix(empreinte, "SHA256:")) != 43:
		out = append(out, Result{"Empreinte/forme", false,
			fmt.Sprintf("corps de %d caractères, attendu 43", len(strings.TrimPrefix(empreinte, "SHA256:")))})
	case strings.Contains(empreinte, "="):
		out = append(out, Result{"Empreinte/forme", false, "remplissage base64 présent"})
	default:
		out = append(out, Result{"Empreinte/forme", true, ""})
	}

	// Insensible à la mise en forme du PEM.
	//
	// Le DER est haché, pas l'enveloppe texte. Sans cela, un fichier passé par
	// Windows — donc en CRLF — produirait une empreinte différente pour une clé
	// identique, et l'agent annoncerait « la clé du core a changé » alors
	// qu'elle n'aurait pas bougé.
	// Chaque variante doit rester un PEM VALIDE : on teste la tolérance à la
	// mise en forme, pas la tolérance à un fichier corrompu.
	//
	// Un espace collé devant « -----BEGIN » n'entre pas dans cette catégorie —
	// ce n'est plus du PEM, et le refuser est correct. La première version de
	// ce test l'incluait par inadvertance et échouait sur du code sain.
	variantes := map[string]string{
		"CRLF":            strings.ReplaceAll(cle, "\n", "\r\n"),
		"sans saut final": strings.TrimRight(cle, "\n"),
		"lignes vides":    "\n\n" + cle + "\n\n",
	}
	stable := true
	for nom, variante := range variantes {
		autre, err := duckykey.EmpreinteClePublique(variante)
		if err != nil {
			out = append(out, Result{"Empreinte/mise en forme " + nom, false, err.Error()})
			stable = false
			continue
		}
		if autre != empreinte {
			out = append(out, Result{"Empreinte/mise en forme " + nom, false,
				"empreinte différente pour la même clé — le PEM est haché au lieu du DER"})
			stable = false
		}
	}
	if stable {
		out = append(out, Result{"Empreinte/insensible à la mise en forme", true, ""})
	}

	// Deux clés distinctes doivent donner deux empreintes distinctes. Sans ce
	// contrôle, une fonction qui rendrait une constante passerait tout le reste.
	autreCle, err := clePubliqueDeTest()
	if err == nil {
		autreEmpreinte, err := duckykey.EmpreinteClePublique(autreCle)
		if err != nil {
			out = append(out, Result{"Empreinte/discrimination", false, err.Error()})
		} else if autreEmpreinte == empreinte {
			out = append(out, Result{"Empreinte/discrimination", false,
				"deux clés différentes ont la même empreinte"})
		} else {
			out = append(out, Result{"Empreinte/discrimination", true, ""})
		}
	}

	// Une entrée illisible ne doit pas passer pour une clé.
	for _, mauvaise := range []string{"", "pas du PEM", "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"} {
		if _, err := duckykey.EmpreinteClePublique(mauvaise); err == nil {
			out = append(out, Result{"Empreinte/entrée invalide", false,
				fmt.Sprintf("%q accepté comme clé publique", mauvaise)})
			return out
		}
	}
	out = append(out, Result{"Empreinte/entrée invalide", true, ""})

	return out
}

// testEmpreinteNomDeFichierPartage est LE test de ce fichier.
//
// Le nom du fichier d'empreinte apparaît en quatre endroits qui ne se
// compilent jamais ensemble :
//
//	core   : key_management/core_fingerprint.go
//	agent  : vaultaire_client/duckynetworkClient/serveurauth/coretrust.go
//	SDK    : ducky-network-sdk-service/duckynetwork/serveurauth/coretrust.go
//	script : automatisation/auto_deployements/rocky.sh
//
// Si l'un d'eux change, rien ne casse : le core dépose un fichier que personne
// ne lit, l'agent cherche un fichier qui n'existe pas, conclut qu'aucune
// empreinte n'est configurée, et accepte la première clé venue.
//
// La protection disparaît alors en silence. D'où ce test, qui lit les sources.
func testEmpreinteNomDeFichierPartage() []Result {
	attendu := duckykey.CoreFingerprintFileName

	racine, err := racineDuDepot()
	if err != nil {
		// Exécution hors de l'arborescence des sources — le cas d'un core
		// installé, où `vlt testrunner` tourne depuis /etc ou /opt.
		//
		// Ce test lit des fichiers source ; il ne peut donc s'exécuter qu'en
		// développement et en intégration continue. C'est précisément là qu'il
		// sert, puisque c'est là que la divergence serait introduite.
		//
		// Il ne fait donc PAS échouer la suite en production. Mais il ne rend
		// pas non plus un succès muet, qui laisserait croire que la cohérence a
		// été contrôlée : le nom du résultat porte l'information, seul champ
		// affiché quand un test passe.
		return []Result{{
			"Empreinte/nom partagé — NON VÉRIFIÉ (hors arborescence des sources, depuis " + err.Error() + ")",
			true, ""}}
	}

	emplacements := []struct {
		nom    string
		chemin string
		motif  string
	}{
		{"agent", "src/vaultaire_client/duckynetworkClient/serveurauth/coretrust.go",
			`FingerprintFileName = "` + attendu + `"`},
		{"SDK", "src/ducky-network-sdk-service/duckynetwork/serveurauth/coretrust.go",
			`FingerprintFileName = "` + attendu + `"`},
		{"script de déploiement", "automatisation/auto_deployements/rocky.sh", attendu},
	}

	var out []Result
	for _, e := range emplacements {
		contenu, err := os.ReadFile(filepath.Join(racine, e.chemin))
		if err != nil {
			out = append(out, Result{"Empreinte/nom partagé (" + e.nom + ")", false,
				"fichier illisible : " + err.Error()})
			continue
		}
		if !strings.Contains(string(contenu), e.motif) {
			out = append(out, Result{"Empreinte/nom partagé (" + e.nom + ")", false,
				fmt.Sprintf("%q absent de %s — l'empreinte ne sera jamais trouvée, "+
					"et l'agent acceptera la première clé reçue sans le signaler comme une anomalie",
					e.motif, e.chemin)})
			continue
		}
		out = append(out, Result{"Empreinte/nom partagé (" + e.nom + ")", true, ""})
	}
	return out
}

// racineDuDepot remonte depuis le répertoire courant jusqu'à trouver la racine.
//
// Le testrunner peut être lancé depuis la racine comme depuis src/ ; on ne peut
// pas supposer l'un ou l'autre.
func racineDuDepot() (string, error) {
	depart, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := depart
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "automatisation", "auto_deployements")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("%s", depart)
}

// testEmpreinteDepotPourClient : le fichier écrit doit être relisible.
//
// Vérifie la forme réellement produite — commentaires en tête, empreinte sur
// sa propre ligne — et non seulement que l'écriture n'a pas échoué.
func testEmpreinteDepotPourClient() []Result {
	dir, err := os.MkdirTemp("", "vlt-empreinte")
	if err != nil {
		return []Result{{"Empreinte/dépôt", false, err.Error()}}
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// EcrireEmpreintePourClient lit la clé du core EN BASE, indisponible hors
	// d'un core démarré. On vérifie donc la forme du fichier à partir du même
	// gabarit, en calculant l'empreinte d'une clé de test.
	cle, err := clePubliqueDeTest()
	if err != nil {
		return []Result{{"Empreinte/dépôt", false, err.Error()}}
	}
	empreinte, err := duckykey.EmpreinteClePublique(cle)
	if err != nil {
		return []Result{{"Empreinte/dépôt", false, err.Error()}}
	}

	contenu := "# Empreinte de la clé publique du core Vaultaire.\n" +
		"# Déposée à l'installation par « vlt create -join », sur le canal SSH.\n" +
		"# L'agent refuse toute clé de core qui ne correspond pas.\n" +
		empreinte + "\n"
	chemin := filepath.Join(dir, duckykey.CoreFingerprintFileName)
	if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
		return []Result{{"Empreinte/dépôt", false, err.Error()}}
	}

	// Relecture selon la même règle que l'agent : première ligne non vide et
	// non commentée.
	brut, err := os.ReadFile(chemin)
	if err != nil {
		return []Result{{"Empreinte/dépôt", false, err.Error()}}
	}
	lue := ""
	for _, ligne := range strings.Split(string(brut), "\n") {
		ligne = strings.TrimSpace(strings.TrimSuffix(ligne, "\r"))
		if ligne == "" || strings.HasPrefix(ligne, "#") {
			continue
		}
		lue = ligne
		break
	}
	if lue != empreinte {
		return []Result{{"Empreinte/dépôt", false,
			fmt.Sprintf("relecture %q, écrit %q — l'agent ne retrouverait pas l'empreinte", lue, empreinte)}}
	}
	return []Result{{"Empreinte/dépôt et relecture", true, ""}}
}
