package sessionmgr

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	networksecurity "vaultaire/ducky-network/networkSecurity"
)

// Longueur de la clé de session, en caractères.
//
// Cette valeur n'est pas un réglage : la chaîne est convertie telle quelle en
// []byte pour servir de clé AES-256, qui en exige exactement 32. La changer
// casserait le chiffrement de toutes les trames.
const sessionKeyLength = 32

// sessionKeyRandomBytes est le nombre d'octets aléatoires tirés pour produire
// ces 32 caractères.
//
// 24 octets → 32 caractères en base64 sans remplissage, exactement :
// l'encodage produit 4 caractères pour 3 octets, et 24 est divisible par 3.
// Aucun caractère « = » de remplissage n'apparaît donc, et la longueur tombe
// juste sans troncature.
const sessionKeyRandomBytes = 24

// GenerateIntegrityKey génère un SessionIntegritykey unique : 32 caractères
// utilisés tels quels comme clé AES-256 une fois convertis en []byte
// (32 caractères ASCII = 32 octets). L'unicité est vérifiée directement contre
// le registre de sessions actif.
//
// # Pourquoi base64url et non hexadécimal
//
// La version précédente tirait 32 octets aléatoires, les encodait en
// hexadécimal — ce qui donne 64 caractères — puis TRONQUAIT à 32 :
//
//	key := hex.EncodeToString(raw)[:32]
//
// La troncature jetait exactement la moitié de l'aléa tiré. Et surtout, le
// résultat n'avait pas l'entropie que sa taille laissait croire : une clé AES
// de 32 octets suggère 256 bits, mais un caractère hexadécimal ne prend que
// 16 valeurs, soit 4 bits utiles. 32 × 4 = 128 bits. La moitié annoncée.
//
// L'écart ne se voyait nulle part : la clé faisait bien 32 octets, AES
// l'acceptait, tout fonctionnait. Seul le décompte des valeurs possibles
// révélait le problème.
//
// base64url porte 64 symboles, donc 6 bits par caractère : 32 × 6 = 192 bits.
//
// # Pourquoi pas 256 bits
//
// Il faudrait 256 valeurs distinctes par octet, donc du binaire brut. Or la
// clé transite dans un protocole où les trames sont découpées sur les sauts de
// ligne : un octet 0x0A tiré au hasard couperait la trame en deux. Le texte
// est ici une contrainte de fond, pas un choix.
//
// 192 bits reste très au-delà de ce qui est atteignable : il faudrait environ
// 2^96 tirages pour espérer une collision. Le gain sur les 128 bits précédents
// est réel, et il ne coûte rien.
//
// # Pourquoi le changement ne casse rien
//
// La clé est générée ici et transmise au client, qui la stocke sans jamais
// l'analyser — aucun appel à hex.DecodeString, aucune vérification de
// longueur ni de format nulle part dans le client ni dans le SDK. Seul
// l'alphabet change, à longueur constante. Les clients d'une version
// antérieure continuent donc de fonctionner sans modification, et il n'y a
// pas de bascule à coordonner.
//
// base64url (RFC 4648 §5) plutôt que le base64 standard : son alphabet est
// A-Z a-z 0-9 - _, sans « + » ni « / ». La clé sert aussi d'identifiant de
// session dans les journaux, et un « / » y serait au mieux gênant.
func (m *Manager) GenerateIntegrityKey() (string, error) {
	const maxRetries = 5

	for i := 0; i < maxRetries; i++ {
		raw := make([]byte, sessionKeyRandomBytes)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("erreur lors de la génération de la clé : %v", err)
		}
		key := base64.RawURLEncoding.EncodeToString(raw)

		// Garde-fou. La longueur découle de l'arithmétique de l'encodage et ne
		// peut pas varier — mais elle est la condition de validité de la clé
		// AES, et une clé trop courte partirait sans bruit jusqu'à un échec de
		// chiffrement très loin d'ici. On préfère échouer sur place.
		if len(key) != sessionKeyLength {
			return "", fmt.Errorf(
				"clé de session de %d caractères au lieu de %d — incohérence interne",
				len(key), sessionKeyLength)
		}

		m.mu.RLock()
		_, exists := m.sessions[key]
		m.mu.RUnlock()

		if !exists {
			return key, nil
		}
	}
	return "", fmt.Errorf("échec de la génération d'une clé unique après %d tentatives", maxRetries)
}

// SeedTrame initialise le suivi de l'ordre des trames pour une session,
// typiquement juste après la poignée de main initiale (Rekey vers le
// SessionIntegritykey réel). initialTrame est la trame qui vient d'être
// traitée (ex "01_01") : UpdateConnectionTrame validera tout ce qui suit à
// partir de là.
func (m *Manager) SeedTrame(sessionID, initialTrame string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.ActualTrame = initialTrame
		s.TrameIsSafe = false
	}
}

// UpdateConnectionTrame vérifie qu'une nouvelle trame suit bien l'ordre
// attendu pour cette session, et met à jour son état (remplace
// ducky-network/sync.UpdateConnectionTrame, qui faisait la même chose sur
// une sync.Map séparée et indépendante du reste de l'état de session).
//
// Une fois la séquence obligatoire terminée (TrameIsSafe == true), l'ordre
// n'est plus vérifié : les trames applicatives (GPO, host, etc.) peuvent
// arriver dans n'importe quel ordre après un login complet.
func (m *Manager) UpdateConnectionTrame(sessionID, newTrame string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session %s introuvable", sessionID)
	}

	if s.TrameIsSafe {
		return nil
	}

	if !networksecurity.IsValidNextTrame(s.ActualTrame, newTrame) {
		return fmt.Errorf("ordre de trame invalide : reçu %s après %s", newTrame, s.ActualTrame)
	}

	s.ActualTrame = newTrame

	if newTrame == networksecurity.ExpectedTrames[len(networksecurity.ExpectedTrames)-1] {
		s.TrameIsSafe = true
	}
	if newTrame == "04_01" {
		s.TrameIsSafe = true
	}

	return nil
}
