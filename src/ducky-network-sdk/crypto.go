package duckynetwork

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
)

// Chiffrement du canal Ducky.
//
// # OAEP, et surtout PAS PKCS#1 v1.5
//
// Le bourrage v1.5 est vulnérable à l'attaque de Bleichenbacher, et le core a
// migré vers OAEP pour cette raison (voir key_decode_encode/oaep_params.go côté
// serveur). Ce SDK utilisait encore PKCS#1 v1.5 : il ne pouvait donc PAS parler
// au core, la poignée de main échouant au déchiffrement.
//
// LES DEUX CÔTÉS DOIVENT ÊTRE STRICTEMENT IDENTIQUES. Un hachage ou un label qui
// diffère produit un échec indistinguable d'une mauvaise clé — donc des heures
// perdues à chercher au mauvais endroit. Ce fichier et son pendant serveur se
// modifient ensemble ou pas du tout.

// oaepHash est la fonction de hachage du bourrage.
//
// Retournée par un constructeur et non stockée : hash.Hash porte un état
// interne, une instance partagée entre deux chiffrements concurrents produirait
// des résultats faux.
func oaepHash() hash.Hash { return sha256.New() }

// oaepLabel est volontairement nil, comme côté serveur.
var oaepLabel []byte = nil

// MaxOAEPPayload retourne la taille maximale chiffrable pour une clé donnée.
//
// OAEP consomme 2*hLen + 2 octets, contre 11 pour PKCS#1 v1.5 : sur RSA-4096 la
// charge utile passe de 501 à 446 octets. Exposée pour que la vérification soit
// possible plutôt que d'être une note de commentaire qui vieillira.
func MaxOAEPPayload(keySizeBytes int) int {
	overhead := 2*sha256.Size + 2
	if keySizeBytes <= overhead {
		return 0
	}
	return keySizeBytes - overhead
}

// encryptRSA chiffre avec la clé publique du serveur.
func encryptRSA(publicKeyPEM, plaintext string) ([]byte, error) {
	pub, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	if max := MaxOAEPPayload(pub.Size()); len(plaintext) > max {
		return nil, fmt.Errorf("charge de %d octets, maximum %d pour cette clé", len(plaintext), max)
	}
	return rsa.EncryptOAEP(oaepHash(), rand.Reader, pub, []byte(plaintext), oaepLabel)
}

// decryptRSA déchiffre avec notre clé privée.
func decryptRSA(privateKeyPEM string, ciphertext []byte) (string, error) {
	priv, err := ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	plain, err := rsa.DecryptOAEP(oaepHash(), rand.Reader, priv, ciphertext, oaepLabel)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// encryptAESGCM chiffre une trame avec la clé de session.
//
// Le nonce est préfixé au chiffré puis l'ensemble est encodé en base64 : c'est
// exactement ce que fait le serveur, et le format doit correspondre au caractère
// près sous peine d'échec d'authentification GCM.
func encryptAESGCM(key []byte, plaintext string) (string, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plaintext), nil)), nil
}

// decryptAESGCM déchiffre une trame reçue.
func decryptAESGCM(key []byte, ciphertextB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("base64 illisible : %w", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	if len(raw) < aead.NonceSize() {
		return "", fmt.Errorf("message trop court pour contenir un nonce")
	}
	nonce, body := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("clé AES de %d octets, 32 attendus pour AES-256", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ParsePublicKey lit une clé publique RSA au format PEM.
func ParsePublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("bloc PEM absent dans la clé publique")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("clé publique illisible : %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("clé publique non RSA")
	}
	return pub, nil
}

// ParsePrivateKey lit une clé privée RSA au format PEM.
//
// Accepte PKCS#8 et PKCS#1 : le core écrit du PKCS#8, mais une clé générée à la
// main avec openssl est souvent en PKCS#1, et refuser cette forme ferait échouer
// l'enrôlement sur un détail sans importance.
func ParsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("bloc PEM absent dans la clé privée")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("clé privée non RSA")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("clé privée illisible : %w", err)
	}
	return key, nil
}

// MarshalPublicKey sérialise une clé publique au format attendu par le core.
func MarshalPublicKey(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// MarshalPrivateKey sérialise une clé privée en PKCS#8, comme le core.
func MarshalPrivateKey(priv *rsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// GenerateKeyPair tire une paire RSA-4096, comme le core.
//
// Sur le matériel courant la génération prend de l'ordre de la seconde : c'est
// acceptable, elle n'a lieu qu'à l'enrôlement.
func GenerateKeyPair() (privatePEM, publicPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", fmt.Errorf("génération de la paire : %w", err)
	}
	if privatePEM, err = MarshalPrivateKey(key); err != nil {
		return "", "", err
	}
	if publicPEM, err = MarshalPublicKey(&key.PublicKey); err != nil {
		return "", "", err
	}
	return privatePEM, publicPEM, nil
}
