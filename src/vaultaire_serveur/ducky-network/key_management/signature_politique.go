package keymanagement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	dbcertificates "vaultaire/core/database/db_certificates"
	"vaultaire/core/logs"
)

// Signature des politiques GPO par le cluster (TO-DO 52).
//
// # Pourquoi une clé DE PLUS, et pas `server_main`
//
// C'est la question qui décide de la valeur de cette fonctionnalité.
//
// `server_main` est la clé de TRANSPORT. L'agent l'obtient du core au moment de
// se connecter (`askkey`), et la confronte à une LISTE d'empreintes de
// confiance — une liste qui peut s'allonger, puisqu'un core déjà de confiance
// peut en annoncer d'autres dans la trame 04_04 (`ApprendreEmpreinte` :
// « TOUT CORE DE CONFIANCE PEUT AJOUTER DE LA CONFIANCE »). C'est un compromis
// assumé pour la découverte : sans lui, distribuer une liste de cores ne
// servirait à rien.
//
// Signer la politique avec cette clé-là n'aurait donc rien prouvé de plus que
// le tunnel. Un nœud entré dans la liste par transitivité aurait signé ses
// propres politiques, et l'agent les aurait acceptées.
//
// La clé de signature est POSÉE À L'INSTALLATION et ne s'apprend jamais en
// route. La confiance de transport peut s'étendre ; celle des politiques, non.
// C'est toute la différence, et c'est ce qui fait que ce n'est pas un ornement.
//
// # Ce que la signature ne couvre PAS, et il faut le dire
//
// Les cores d'un cluster partagent une base (`certificates.name` est unique) :
// un core dont la base est compromise détient cette clé comme il détient toutes
// les autres. La signature ne protège donc pas d'un core compromis de
// l'intérieur — seul un secret hors de la base le ferait, et ce serait un autre
// travail, avec un autre coût d'exploitation.
//
// Ce qu'elle apporte : la politique porte sa preuve AVEC elle, indépendamment
// du canal. Un document réassemblé, mis en cache, rejoué, ou servi par un nœud
// entré dans la confiance de transport ne s'applique plus sans la clé du
// cluster.

// GPOSigningKeyName est le nom du certificat de signature des politiques.
//
// Dans la même table que les autres : un cluster tient sur une base commune, et
// la clé y est donc partagée par tous ses cores sans aucun travail de
// réplication. C'est aussi ce qui fait qu'un agent n'a qu'une clé à connaître,
// quel que soit le core qui lui répond.
const GPOSigningKeyName = "gpo_signing"

// GPOPublicKeyFileName est le nom du fichier déposé sur la machine.
//
// À côté de `core_key_fingerprint`, et pour la même raison : le canal SSH de
// `create -c … --join` est déjà authentifié, c'est le seul moment où l'on peut
// poser une confiance sans en supposer une autre.
const GPOPublicKeyFileName = "gpo_signing_key.pem"

// Generate_GPO_Signing_Key amorce la clé de signature des politiques.
//
// Idempotente, et pour la même raison que la clé SSH de déploiement : une clé
// régénérée ferait refuser leurs politiques à toutes les machines qui portent
// l'ancienne. Seule son ABSENCE de la base autorise une génération — une erreur
// de lecture, elle, est remontée telle quelle.
func Generate_GPO_Signing_Key() error {
	_, err := GetPrivateKeyPEMFromDB(GPOSigningKeyName)
	if err == nil {
		return nil
	}
	if !estCertificatIntrouvable(err) {
		return fmt.Errorf("lecture de la clé de signature des politiques : %w", err)
	}

	privee, publique, err := GenerateKeyRSA(4096)
	if err != nil {
		return err
	}
	if err := SaveKeyPairToDB(GPOSigningKeyName, "rsa_keypair",
		"Clé de signature des politiques GPO, partagée par les cores du cluster",
		privee, publique); err != nil {
		return err
	}
	logs.Write_Log("INFO", "keymanagement: clé de signature des politiques GPO générée ("+GPOSigningKeyName+")")
	return nil
}

// estCertificatIntrouvable distingue « absent » de « illisible ».
//
// La sentinelle du paquet certificats est la source sûre ; la comparaison de
// message est le repli pour les chemins qui ne l'enveloppent pas encore.
func estCertificatIntrouvable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, dbcertificates.ErrCertificatIntrouvable) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "non trouvé")
}

// SignerLivraison signe une livraison de politique.
//
// # Ce qui est signé, et pourquoi pas seulement le document
//
// La chaîne signée lie la politique à SON DESTINATAIRE :
//
//	vaultaire-gpo-v1\n<computeur_id>\n<scope>\n<username>\n<empreinte>\n<somme>
//
// Signer les seuls octets du document aurait laissé une politique valide
// rejouable d'une machine à l'autre : les politiques de scope machine ne
// nomment pas la machine, et servir à un poste la politique d'un autre est
// exactement l'attaque qu'on veut fermer. Le nom d'utilisateur est là pour la
// même raison au scope user.
//
// La somme de contrôle suffit à couvrir le document : l'agent la vérifie contre
// les octets qu'il a réassemblés AVANT de vérifier la signature, si bien que
// signer la somme revient à signer le document — sans faire recalculer à
// l'agent une empreinte canonique qu'il ne sait pas produire, et qu'il ne doit
// pas apprendre à produire (deux implémentations d'un même hachage finissent
// par diverger).
//
// Le préfixe `vaultaire-gpo-v1` est une séparation de domaine : la même clé ne
// pourra jamais signer autre chose qui soit pris pour une politique, et la
// version permet de changer la composition un jour sans qu'une signature
// ancienne reste valable pour la nouvelle règle.
func SignerLivraison(computeurID, scope, username, empreinte, somme string) (string, error) {
	pemPrivee, err := GetPrivateKeyPEMFromDB(GPOSigningKeyName)
	if err != nil {
		return "", fmt.Errorf("clé de signature des politiques : %w", err)
	}

	clef, err := LireClePriveePEM(pemPrivee)
	if err != nil {
		return "", err
	}

	// RSA-PSS SHA-256, et non PKCS#1 v1.5.
	//
	// Le même raisonnement que pour le passage de PKCS#1 v1.5 à OAEP côté
	// chiffrement : quand les deux extrémités sont à nous, rien ne justifie de
	// retenir la construction la plus ancienne. Le sel aléatoire de PSS rend
	// deux signatures du même document différentes, ce qui ne gêne personne ici
	// — la signature voyage avec sa livraison et n'est jamais comparée.
	condense := sha256.Sum256([]byte(CorpsSigne(computeurID, scope, username, empreinte, somme)))
	sig, err := rsa.SignPSS(rand.Reader, clef, crypto.SHA256, condense[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return "", fmt.Errorf("signature de la politique : %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// LireClePriveePEM lit une clé privée RSA, quel que soit son encodage.
//
// PKCS#1 d'abord, parce que c'est ce que SaveKeyPairToDB écrit ; PKCS#8 en
// repli, parce qu'une clé posée à la main dans la base peut l'être. Échouer sur
// le second format aurait donné « bourrage invalide » pour dire « ce n'est pas
// l'encodage que j'attendais ».
func LireClePriveePEM(pemPrivee string) (*rsa.PrivateKey, error) {
	bloc, _ := pem.Decode([]byte(pemPrivee))
	if bloc == nil {
		return nil, fmt.Errorf("clé de signature des politiques : PEM illisible")
	}
	if clef, err := x509.ParsePKCS1PrivateKey(bloc.Bytes); err == nil {
		return clef, nil
	}
	brute, err := x509.ParsePKCS8PrivateKey(bloc.Bytes)
	if err != nil {
		return nil, fmt.Errorf("clé de signature des politiques : %w", err)
	}
	clef, ok := brute.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("clé de signature des politiques : type de clé inattendu")
	}
	return clef, nil
}

// CorpsSigne compose la chaîne signée.
//
// Exportée et partagée par les deux côtés du réseau — ici pour signer, dans
// l'agent pour vérifier. Les deux implémentations sont figées par des tests
// jumeaux : une divergence d'un seul octet ferait refuser toutes les politiques
// du parc, et le message ne dirait pas pourquoi.
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

// ClePubliqueSignaturePEM rend la clé publique de signature, telle qu'elle est
// en base.
//
// Du PEM et non une ligne `authorized_keys` : l'agent la lit avec la
// bibliothèque standard, et lui faire porter un format SSH l'aurait obligé à
// prendre une dépendance entière — golang.org/x/crypto — pour une seule
// fonction d'analyse. L'agent n'a aujourd'hui que deux dépendances, et
// l'inventaire du point 80 demande qu'on justifie chacune : celle-ci ne se
// justifiait pas.
//
// Pour l'œil, c'est l'EMPREINTE qui sert de comparaison — une ligne, la même
// des deux côtés.
func ClePubliqueSignaturePEM() (string, error) {
	pemPublique, err := GetPublicKeyPEMFromDB(GPOSigningKeyName)
	if err != nil {
		return "", fmt.Errorf("clé de signature des politiques : %w", err)
	}
	if bloc, _ := pem.Decode([]byte(pemPublique)); bloc == nil {
		return "", fmt.Errorf("clé de signature des politiques : PEM illisible")
	}
	return pemPublique, nil
}

// EmpreinteCleSignature rend l'empreinte de la clé de signature.
//
// Même forme que celle du core (« SHA256:… » sur le DER) : c'est la valeur
// qu'un administrateur compare entre le core et une machine quand une politique
// est refusée, et deux formes d'empreinte dans le même produit feraient douter
// de la comparaison.
func EmpreinteCleSignature() (string, error) {
	pemPublique, err := ClePubliqueSignaturePEM()
	if err != nil {
		return "", err
	}
	return EmpreinteClePublique(pemPublique)
}

// EcrireClePolitiquePourClient dépose la clé publique de signature dans le
// répertoire préparé pour une machine, à côté du fichier d'empreinte.
//
// 0644 : une clé PUBLIQUE n'est pas un secret, et sa lecture doit rester
// possible pour le diagnostic — « cette machine attend-elle la bonne clé »
// est la première question devant une politique refusée.
func EcrireClePolitiquePourClient(repertoire string) error {
	cle, err := ClePubliqueSignaturePEM()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(repertoire, 0o700); err != nil {
		return fmt.Errorf("création de %s : %w", repertoire, err)
	}
	contenu := "# Clé publique de signature des politiques GPO du cluster Vaultaire.\n" +
		"# Déposée à l'installation par « vlt create -join », sur le canal SSH.\n" +
		"# Une politique signée qui ne correspond pas à cette clé est refusée.\n" +
		cle
	chemin := filepath.Join(repertoire, GPOPublicKeyFileName)
	if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
		return fmt.Errorf("écriture de %s : %w", chemin, err)
	}
	return nil
}
