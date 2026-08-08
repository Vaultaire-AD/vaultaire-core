package keymanagement

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Empreinte de la clé publique du core, à destination des machines clientes.
//
// # Pourquoi le core la publie
//
// Un agent qui reçoit la clé du core par la trame `askkey` n'a aucun moyen de
// savoir si elle vient bien du core : le canal n'est pas authentifié à ce
// moment-là — c'est même la raison d'être de l'échange, obtenir de quoi
// l'authentifier ensuite.
//
// L'empreinte casse ce cercle, à condition d'arriver par un AUTRE chemin.
// Ce chemin existe déjà : `vlt create -join` se connecte en SSH à la machine,
// donc sur un canal authentifié par une clé, et y dépose des fichiers. Un
// fichier de plus ne coûte rien, et il porte la garantie que la trame `askkey`
// ne peut pas porter.
//
// # Ce qui rend cette empreinte fiable
//
// Rien, prise isolément — c'est une chaîne de caractères. Ce qui la rend fiable
// est le canal qui l'apporte : si l'attaquant peut modifier ce que SSH dépose
// sur la machine, il a déjà bien mieux à faire que substituer une clé de core.
//
// L'empreinte n'est donc pas un secret. Sa publication n'aide personne : elle
// ne permet pas de fabriquer la clé privée correspondante. C'est son intégrité
// en transit qui compte.

// CoreFingerprintFileName doit correspondre à serveurauth.FingerprintFileName
// côté agent et côté SDK. Trois copies de la même constante, parce que les
// trois vivent dans des modules Go distincts qui ne se voient pas.
//
// Un test vérifie qu'elles ne divergent pas — c'est exactement le genre de
// valeur qui se désynchronise en silence, et dont la désynchronisation se
// manifeste par « l'empreinte n'est jamais vérifiée » plutôt que par une
// erreur.
const CoreFingerprintFileName = "core_key_fingerprint"

// EmpreinteClePublique calcule l'empreinte d'une clé publique au format PEM.
//
// Le DER est haché, pas le PEM : l'enveloppe texte varie — saut de ligne final,
// terminaisons CRLF sur un fichier passé par Windows — sans que la clé change.
// Une empreinte sensible à la mise en forme produirait des refus sur une clé
// pourtant identique, et le message dirait « la clé du core a changé » alors
// qu'elle n'aurait pas bougé.
//
// Forme « SHA256:<base64> », celle d'OpenSSH : un administrateur habitué à
// `ssh-keygen -lf` la reconnaît sans explication.
func EmpreinteClePublique(pemContent string) (string, error) {
	bloc, _ := pem.Decode([]byte(pemContent))
	if bloc == nil {
		return "", fmt.Errorf("clé publique illisible : ce n'est pas du PEM")
	}
	if len(bloc.Bytes) == 0 {
		return "", fmt.Errorf("clé publique vide")
	}
	somme := sha256.Sum256(bloc.Bytes)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(somme[:]), nil
}

// EmpreinteDuCore rend l'empreinte de la clé que le core sert aux agents.
//
// Elle est calculée à partir de GetPublicKey() — la MÊME source que celle
// employée pour répondre à `askkey`. Passer par une autre source rendrait
// possible qu'elles divergent, et l'agent refuserait alors une clé légitime.
func EmpreinteDuCore() (string, error) {
	cle := GetPublicKey()
	if cle == "" || cle == "err" {
		return "", fmt.Errorf("clé publique du core indisponible")
	}
	return EmpreinteClePublique(cle)
}

// EcrireEmpreintePourClient dépose le fichier d'empreinte dans le répertoire
// préparé pour une machine, celui que `-join` recopie ensuite par SCP.
//
// 0644 : l'empreinte n'est pas un secret, et sa lecture doit rester possible
// pour le diagnostic. Le répertoire, lui, est en 0700.
func EcrireEmpreintePourClient(repertoire string) error {
	empreinte, err := EmpreinteDuCore()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(repertoire, 0o700); err != nil {
		return fmt.Errorf("création de %s : %w", repertoire, err)
	}
	contenu := "# Empreinte de la clé publique du core Vaultaire.\n" +
		"# Déposée à l'installation par « vlt create -join », sur le canal SSH.\n" +
		"# L'agent refuse toute clé de core qui ne correspond pas.\n" +
		empreinte + "\n"
	chemin := filepath.Join(repertoire, CoreFingerprintFileName)
	if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
		return fmt.Errorf("écriture de %s : %w", chemin, err)
	}
	return nil
}
