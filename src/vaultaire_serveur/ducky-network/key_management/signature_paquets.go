package keymanagement

import (
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"

	"vaultaire/core/database"
	dbcertificates "vaultaire/core/database/db_certificates"
	"vaultaire/core/logs"
	"vaultaire/core/paquetagent"
)

// La clé de signature des paquets d'agent — TO-DO 113.
//
// # Le calque de gpo_signing, et pourquoi une clé de PLUS
//
// Même table (`certificates`, donc partagée par le cluster sans réplication),
// même amorçage idempotent, même dépôt à l'installation par le SCP de `--join`.
// Mais une clé distincte : deux rôles de gravité différente ne doivent pas
// dépendre d'une seule clé. Le jour où l'une doit être révoquée, on ne doit pas
// casser l'autre du même geste. Le domaine de signature (`vaultaire-pkg-v1`)
// est distinct lui aussi — voir paquetagent.Domaine.
//
// Ce n'est pas une question d'exposition : un core compromis exécute déjà du
// code root sur le parc par un `file_deploy`. La signature ferme autre chose —
// un paquet falsifié servi par le DÉPÔT, qui est en lecture anonyme (point
// 114) et qu'un site sans Internet alimente à la main.
//
// # JAMAIS régénérée
//
// Toutes les machines qui portent l'ancienne refuseraient leurs paquets. Seule
// l'ABSENCE de la ligne autorise une génération ; une ligne présente SANS clé
// privée est le mode hors ligne (voir OublierClePriveePaquets), pas un manque.

// PkgSigningKeyName est le nom du certificat en base.
const PkgSigningKeyName = "pkg_signing"

// PkgPublicKeyFileName est le fichier déposé sur la machine, à côté de
// gpo_signing_key.pem — `rocky.sh` et `debian.sh` rangent tous les *.pem dans
// /etc/vaultaire_client/.ssh/ sans liste à tenir.
const PkgPublicKeyFileName = "pkg_signing_key.pem"

// Generate_Pkg_Signing_Key amorce la clé, si et seulement si la ligne manque.
func Generate_Pkg_Signing_Key() error {
	_, err := dbcertificates.GetCertificateByName(PkgSigningKeyName)
	if err == nil {
		return nil
	}
	if !estCertificatIntrouvable(err) {
		return fmt.Errorf("lecture de la clé de signature des paquets : %w", err)
	}
	privee, publique, err := GenerateKeyRSA(4096)
	if err != nil {
		return err
	}
	if err := SaveKeyPairToDB(PkgSigningKeyName, "rsa_keypair",
		"Clé de signature des paquets d'agent, partagée par les cores du cluster",
		privee, publique); err != nil {
		return err
	}
	logs.Write_Log("INFO", "keymanagement: clé de signature des paquets générée ("+PkgSigningKeyName+")")
	return nil
}

// ClePubliquePaquetsPEM rend la clé publique telle qu'elle est en base.
func ClePubliquePaquetsPEM() (string, error) {
	pemPublique, err := GetPublicKeyPEMFromDB(PkgSigningKeyName)
	if err != nil {
		return "", fmt.Errorf("clé de signature des paquets : %w", err)
	}
	if _, err := paquetagent.LireClesPubliques([]byte(pemPublique)); err != nil {
		return "", fmt.Errorf("clé de signature des paquets : %w", err)
	}
	return pemPublique, nil
}

// EmpreinteClePaquets rend « SHA256:… », la valeur qu'on compare entre le core,
// l'enveloppe d'un paquet et le fichier d'une machine.
func EmpreinteClePaquets() (string, error) {
	pemPublique, err := ClePubliquePaquetsPEM()
	if err != nil {
		return "", err
	}
	return EmpreinteClePublique(pemPublique)
}

// ClePriveePaquets rend la clé privée, ou dit qu'elle est hors ligne.
func ClePriveePaquets() (*rsa.PrivateKey, error) {
	cert, err := dbcertificates.GetCertificateByName(PkgSigningKeyName)
	if err != nil {
		return nil, fmt.Errorf("clé de signature des paquets : %w", err)
	}
	if cert.PrivateKeyData == nil || *cert.PrivateKeyData == "" {
		return nil, fmt.Errorf("la clé privée de signature des paquets n'est pas sur ce core " +
			"(mode hors ligne) : signez avec --key <fichier>")
	}
	return paquetagent.LireClePrivee([]byte(*cert.PrivateKeyData))
}

// OublierClePriveePaquets retire la clé privée de la base, la publique reste.
//
// C'est le passage au mode hors ligne : on exporte la clé privée, on la range
// ailleurs, puis on l'efface d'ici. Les machines ne voient aucune différence —
// leur clé de confiance est la publique, inchangée. L'amorçage ne régénère
// pas : la ligne existe.
func OublierClePriveePaquets() error {
	db := database.GetDatabase()
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	if _, err := ClePubliquePaquetsPEM(); err != nil {
		return fmt.Errorf("refus : la clé publique doit rester lisible en base : %w", err)
	}
	if _, err := db.Exec(`UPDATE certificates SET private_key_data = NULL WHERE name = ?`,
		PkgSigningKeyName); err != nil {
		return fmt.Errorf("effacement de la clé privée : %w", err)
	}
	logs.Write_Log("SECURITY", "keymanagement: clé privée de signature des paquets retirée de la base "+
		"(mode hors ligne)")
	return nil
}

// EcrireClePaquetsPourClient dépose la clé publique dans le répertoire préparé
// pour une machine. Posée À L'INSTALLATION, jamais apprise en route : faire
// demander à l'agent la clé qui juge ce qu'on lui envoie n'aurait aucun sens.
//
// 0644 : une clé publique n'est pas un secret, et « cette machine attend-elle
// la bonne clé » doit pouvoir se lire sans être root.
func EcrireClePaquetsPourClient(repertoire string) error {
	cle, err := ClePubliquePaquetsPEM()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(repertoire, 0o700); err != nil {
		return fmt.Errorf("création de %s : %w", repertoire, err)
	}
	contenu := "# Clé publique de signature des paquets d'agent du cluster Vaultaire.\n" +
		"# Déposée à l'installation par « vlt create -join », sur le canal SSH.\n" +
		"# Un paquet dont le manifeste n'est pas signé par une clé de ce fichier est refusé.\n" +
		"# Ce fichier peut porter DEUX clés pendant une rotation : l'ancienne et la suivante.\n" +
		cle
	chemin := filepath.Join(repertoire, PkgPublicKeyFileName)
	if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
		return fmt.Errorf("écriture de %s : %w", chemin, err)
	}
	return nil
}

// CertificatsIndelebiles nomme les clés que `certificate delete` refuse.
//
// Chacune est amorcée au démarrage SI ELLE MANQUE : la supprimer, c'est en
// faire générer une autre au redémarrage suivant — et tout le parc, qui porte
// l'ancienne (empreinte du core, clé des GPO, clé des paquets), refuse alors
// le core, ses politiques ou ses paquets. Rien ne le répare sinon repasser sur
// chaque machine. Un certificat TLS se régénère sans dommage ; celles-ci non.
var CertificatsIndelebiles = []string{
	ServerMainKeyName,
	ServerLoginClientKeyName,
	GPOSigningKeyName,
	PkgSigningKeyName,
}
