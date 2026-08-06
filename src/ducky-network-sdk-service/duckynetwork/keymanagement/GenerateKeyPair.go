package keymanagement

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"duckynetworkclient/V1/duckynetwork/storage"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// KeyBits est la taille des clés générées.
//
// 4096 comme partout ailleurs dans le produit. Le core refuse en dessous de
// 2048 ; rester aligné évite d'avoir à se demander, devant un refus, si c'est la
// taille ou autre chose.
const KeyBits = 4096

// GenerateClientKeyPair produit la paire du service et l'écrit sur disque.
//
// # La clé privée ne quitte jamais cet hôte
//
// Elle est produite ici et n'est jamais transmise : seule la publique part, en
// 01_07. C'est toute la différence avec un agent de poste, dont le core génère
// la paire et livre la privée avec sa configuration.
//
// Retourne la clé publique au format PEM, celle qu'il faut envoyer au core.
func GenerateClientKeyPair() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		return "", fmt.Errorf("génération de la paire RSA : %w", err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("sérialisation de la clé publique : %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	if err := os.MkdirAll(storage.KeyPath, 0700); err != nil {
		return "", fmt.Errorf("création de %s : %w", storage.KeyPath, err)
	}

	// La PRIVÉE d'abord, en 0600.
	//
	// L'ordre compte : si l'écriture de la publique échoue, on a une privée sans
	// publique, ce qui est réparable — la publique se redérive de la privée.
	// L'inverse laisserait une publique orpheline, dont rien ne dit qu'elle ne
	// correspond à aucune clé détenue.
	if err := os.WriteFile(filepath.Join(storage.KeyPath, "private_key.pem"), privatePEM, 0600); err != nil {
		return "", fmt.Errorf("écriture de la clé privée : %w", err)
	}
	if err := os.WriteFile(filepath.Join(storage.KeyPath, "public.pem"), publicPEM, 0644); err != nil {
		return "", fmt.Errorf("écriture de la clé publique : %w", err)
	}
	return string(publicPEM), nil
}

// HasClientKeys indique si la paire du service est déjà en place.
func HasClientKeys() bool {
	_, err := os.Stat(filepath.Join(storage.KeyPath, "private_key.pem"))
	return err == nil
}
