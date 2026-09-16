package dbenrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// SecretPrefix rend une clé d'enrôlement reconnaissable dans un fichier de
// configuration ou un journal de déploiement, et permet de la détecter si elle
// est collée au mauvais endroit.
const SecretPrefix = "VLT-ENR-"

// GenerateSecret tire une clé d'enrôlement de 128 bits.
//
// Elle est retournée UNE FOIS à l'appelant et n'est jamais réécrite : seul son
// condensat part en base.
func GenerateSecret() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("génération de la clé d'enrôlement : %w", err)
	}
	return SecretPrefix + hex.EncodeToString(raw), nil
}

// HashSecret retourne le condensat stocké en base.
//
// SHA-256 nu et non un dérivé lent façon mot de passe, parce que le secret n'est
// pas choisi par un humain : 128 bits d'entropie réelle ne se retrouvent pas par
// force brute, quel que soit le coût de la fonction. Un dérivé lent
// ralentirait la vérification sans rien ajouter.
//
// La recherche se fait PAR le condensat, qui est indexé unique. Il n'y a donc
// aucune comparaison de secret à effectuer, et aucune fuite par le temps de
// réponse à craindre.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hex.EncodeToString(sum[:])
}
