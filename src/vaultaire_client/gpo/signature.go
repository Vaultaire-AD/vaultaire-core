package gpo

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
)

// Vérification de la signature des politiques (TO-DO 52).
//
// # Ce que cela ajoute au tunnel
//
// Le tunnel Ducky authentifie le CORE : l'agent vérifie sa clé publique contre
// une liste d'empreintes de confiance. Mais cette liste peut s'allonger en
// route — un core déjà de confiance peut en annoncer d'autres dans la 04_04 —,
// et c'est un compromis assumé pour que la découverte serve à quelque chose.
//
// La clé de signature, elle, est POSÉE À L'INSTALLATION et ne s'apprend jamais.
// La confiance de transport peut s'étendre ; celle des politiques, non. Un nœud
// entré dans la liste par transitivité peut donc parler à l'agent, mais pas lui
// faire appliquer une politique.
//
// La signature couvre aussi ce que le tunnel ne voit pas : un document
// réassemblé à partir de fragments, mis en cache, ou rejoué plus tard.
//
// # Ce qu'elle ne couvre PAS
//
// Les cores d'un cluster partagent une base : un core dont la base est
// compromise détient cette clé. La signature ne protège pas de cela, et il faut
// le savoir plutôt que de croire le contraire.

// PrefixeSignature et PrefixeSignatureExigee ouvrent les lignes de queue du
// manifeste.
//
// Déclarés des deux côtés du réseau et figés par des tests jumeaux : rien ne
// lie ces chaînes à la compilation, et les faire diverger ferait ignorer la
// signature en silence — c'est-à-dire produire exactement l'apparence de la
// sécurité sans la sécurité.
const (
	PrefixeSignature       = "sig:"
	PrefixeSignatureExigee = "sigreq:"
)

// NomFichierCleSignature est le fichier déposé par « create -c … --join », à
// côté de l'empreinte du core.
const NomFichierCleSignature = "gpo_signing_key.pem"

var (
	cleMu        sync.Mutex
	cleChargee   bool
	clePolitique *rsa.PublicKey
)

// CheminCleSignature rend le chemin attendu de la clé.
//
// Dérivé de la configuration comme les autres fichiers de confiance, jamais
// codé en dur : c'est le défaut que le point 94 a corrigé pour les clés du
// core, et il n'y a pas de raison de le réintroduire ici.
func CheminCleSignature() string {
	return filepath.Join(storage.KeyPath, NomFichierCleSignature)
}

// ClePolitique rend la clé de signature du cluster, ou nil si la machine n'en a
// pas.
//
// Lue une fois puis mémorisée : elle est posée à l'installation et ne change
// pas en cours de route. Une absence est mémorisée aussi — sans cela, chaque
// cycle relirait un fichier dont on sait déjà qu'il n'existe pas.
func ClePolitique() *rsa.PublicKey {
	cleMu.Lock()
	defer cleMu.Unlock()

	if cleChargee {
		return clePolitique
	}
	cleChargee = true

	contenu, err := os.ReadFile(CheminCleSignature())
	if err != nil {
		if !os.IsNotExist(err) {
			logs.Write_log("WARNING", "GPO: cle de signature illisible : "+err.Error())
		}
		return nil
	}

	cle, err := LireClePublique(contenu)
	if err != nil {
		// Une clé présente mais illisible est dite FORT : la machine croit
		// vérifier et ne vérifie rien.
		logs.Write_log("ERROR", "GPO: cle de signature des politiques inutilisable : "+err.Error())
		return nil
	}

	clePolitique = cle
	logs.Write_log("INFO", "GPO: signatures de politique verifiees avec la cle "+
		CheminCleSignature())
	return clePolitique
}

// LireClePublique analyse le fichier de clé.
//
// Du PEM, parce que c'est ce que le core dépose et ce que la bibliothèque
// standard sait lire : porter un format SSH aurait coûté à l'agent une
// dépendance entière pour une seule fonction d'analyse. Les lignes de
// commentaire qui précèdent le bloc sont ignorées par pem.Decode.
//
// Exportée pour être éprouvée sans fichier.
func LireClePublique(contenu []byte) (*rsa.PublicKey, error) {
	bloc, _ := pem.Decode(contenu)
	if bloc == nil {
		return nil, fmt.Errorf("aucun bloc PEM dans le fichier de clé")
	}

	if brute, err := x509.ParsePKIXPublicKey(bloc.Bytes); err == nil {
		cle, ok := brute.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("clé de signature : type de clé inattendu")
		}
		return cle, nil
	}

	// Repli PKCS#1 : une base plus ancienne peut porter ce format, et échouer
	// ici donnerait « asn1 : structure error » pour dire « ce n'est pas
	// l'encodage que j'attendais ».
	cle, err := x509.ParsePKCS1PublicKey(bloc.Bytes)
	if err != nil {
		return nil, fmt.Errorf("clé de signature illisible : %w", err)
	}
	return cle, nil
}

// CorpsSigne compose la chaîne signée par le core.
//
// Jumelle de keymanagement.CorpsSigne côté core, et figée par un test des deux
// côtés : une divergence d'un seul octet ferait refuser toutes les politiques
// du parc, avec un message qui ne dirait pas pourquoi.
func CorpsSigne(computeurID, scope, username, empreinte, somme string) string {
	return strings.Join([]string{
		"vaultaire-gpo-v1",
		strings.TrimSpace(computeurID),
		strings.TrimSpace(scope),
		strings.TrimSpace(username),
		strings.TrimSpace(empreinte),
		strings.TrimSpace(somme),
	}, "\n")
}

// VerifierSignature contrôle la signature d'une livraison.
//
// Rend nil si la politique peut être appliquée. Les quatre cas, et ce qui les
// sépare :
//
//   - pas de clé sur la machine : on ne peut RIEN vérifier. La politique passe,
//     et l'exigence du core est ignorée — refuser ici couperait les GPO d'un
//     parc installé avant cette version, sans que l'administrateur ait rien
//     fait ni rien vu venir.
//   - clé présente, signature présente : elle doit être valide. Toujours, quelle
//     que soit l'exigence : une signature fausse n'est pas l'absence d'une
//     signature, c'est un document qu'on a tenté de faire passer.
//   - clé présente, signature absente, exigence posée : refus.
//   - clé présente, signature absente, exigence non posée : la politique passe,
//     et le journal le dit — c'est l'état de migration, et il doit se voir.
func VerifierSignature(computeurID, scope, username, empreinte, somme, signature string, exigee bool) error {
	cle := ClePolitique()
	if cle == nil {
		if exigee {
			logs.Write_log("WARNING",
				"GPO: le core exige des politiques signées, mais cette machine n'a pas de clé "+
					"de signature — déposez "+NomFichierCleSignature+" pour que la vérification ait lieu")
		}
		return nil
	}

	signature = strings.TrimSpace(signature)
	if signature == "" {
		if exigee {
			return fmt.Errorf("politique non signée alors que le core exige une signature")
		}
		logs.Write_log("WARNING",
			"GPO: politique non signée acceptée — le core ne signe pas encore, "+
				"ou sa clé de signature est indisponible")
		return nil
	}

	brute, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("signature illisible : %w", err)
	}

	condense := sha256.Sum256([]byte(CorpsSigne(computeurID, scope, username, empreinte, somme)))
	if err := rsa.VerifyPSS(cle, crypto.SHA256, condense[:], brute, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}); err != nil {
		// Le message ne dit pas ce qui diffère, et c'est voulu : l'agent ne sait
		// pas si c'est la machine, l'empreinte ou la somme qui ne correspond
		// pas, et l'inventer donnerait une piste fausse. Ce qu'il sait, c'est
		// que ce document n'a pas été signé pour lui.
		return fmt.Errorf("signature invalide pour cette machine : %w", err)
	}
	return nil
}

// lireLignesSignature cherche les lignes de queue du manifeste.
//
// PAR PRÉFIXE et jamais par rang : les six champs du manifeste se lisent par
// position, et toute ligne ajoutée après coup se reconnaît à son préfixe — même
// recette que la cadence. Un manifeste d'un core d'une version antérieure n'en
// porte aucune, et la fonction rend « pas de signature, pas d'exigence », qui
// est exactement le comportement d'avant.
func lireLignesSignature(lignes []string) (signature string, exigee bool) {
	for _, l := range lignes {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, PrefixeSignature):
			signature = strings.TrimSpace(strings.TrimPrefix(l, PrefixeSignature))
		case strings.HasPrefix(l, PrefixeSignatureExigee):
			exigee = strings.TrimSpace(strings.TrimPrefix(l, PrefixeSignatureExigee)) == "1"
		}
	}
	return signature, exigee
}

// oublierCle vide la mémoire de la clé.
//
// Uniquement pour les tests : la clé est posée à l'installation et ne change
// pas en service, donc rien en production n'a de raison de la relire.
func oublierCle() {
	cleMu.Lock()
	cleChargee = false
	clePolitique = nil
	cleMu.Unlock()
}
