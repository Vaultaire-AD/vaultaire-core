package serveurauth

import (
	"bytes"
	"crypto/rand"
	"fmt"

	keyencodedecode "duckynetwork/duckynetwork/key_encode_decode"
	"duckynetwork/duckynetwork/logs"
	"duckynetwork/duckynetwork/sendmessage"
	"duckynetwork/duckynetwork/storage"
	tramesmanager "duckynetwork/duckynetwork/trames_manager"
)

// ErrIdentityRejected : le core ne reconnaît plus notre identité.
//
// Sa réponse 01_02 est chiffrée avec la clé publique de l'identifiant annoncé ;
// ne pas savoir la lire signifie que le core ne nous connaît plus sous cet
// identifiant. Réessayer avec la même paire ne mènera jamais nulle part : il
// faut se réenrôler.
var ErrIdentityRejected = fmt.Errorf("identité refusée par le core")

// ErrServerNotAuthentic : le défi n'est pas revenu intact.
//
// À traiter comme une tentative d'interposition, pas comme une panne. On ferme
// et on ne réessaie pas en boucle : réessayer contre un serveur qui échoue au
// défi, c'est lui donner d'autres occasions.
var ErrServerNotAuthentic = fmt.Errorf("le serveur a échoué au défi d'authentification")

// challengeSize est la taille du défi, en octets.
//
// Seize octets aléatoires : deviner la valeur attendue est hors de portée, et la
// trame reste très en dessous des 446 octets utiles d'une charge RSA-OAEP sur
// clé 4096.
const challengeSize = 16

// Handshake exécute 01_01 puis vérifie 01_02.
//
// # C'est ici que le SERVEUR est authentifié, pas nous
//
// On tire un aléa, on l'envoie chiffré avec la clé publique du core, et on
// attend qu'il revienne. Seul le détenteur de la clé privée correspondante peut
// l'avoir lu ; le renvoyer PROUVE qu'il l'a. Un serveur qui aurait substitué sa
// clé pendant le « askkey » ne peut pas déchiffrer notre 01_01, donc ne peut pas
// renvoyer le bon aléa.
//
// La vérification n'est donc pas une formalité : la sauter reviendrait à faire
// confiance à n'importe quel serveur ayant réussi à nous donner une clé publique.
//
// La réciproque — nous prouver À LUI — se fait dans le même échange, mais dans
// l'autre sens : le core chiffre 01_02 avec la clé publique de l'identifiant
// annoncé, et seul son vrai propriétaire peut la lire. Un défi explicite en
// retour serait redondant.
//
// À la sortie, IsSafe est vrai et SessionKey porte la clé du tunnel : toutes les
// trames suivantes partiront en AES-GCM.
func Handshake(session *storage.DuckySession, serverPublicKeyPEM, privateKeyPEM string) error {
	challenge := make([]byte, challengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("génération du défi : %w", err)
	}

	// IsSafe est faux : SendMessage chiffre donc la trame entière avec la clé
	// publique du core. Le défi n'a pas à être chiffré une seconde fois.
	session.IsSafe = false
	hello := sendmessage.BuildClientTrame(
		"01_01", "server_central", "INIT", session.Username, session.ComputeurID, string(challenge))
	if err := sendmessage.SendMessage(hello, session, serverPublicKeyPEM); err != nil {
		return fmt.Errorf("envoi de 01_01 : %w", err)
	}

	payload, err := tramesmanager.ReadPayload(session)
	if err != nil {
		return fmt.Errorf("lecture de 01_02 : %w", err)
	}
	plain, err := keyencodedecode.DecryptMessageWithPrivate(privateKeyPEM, payload)
	if err != nil {
		return fmt.Errorf("%w : %v", ErrIdentityRejected, err)
	}

	trames := tramesmanager.ParseTrames(plain)
	if trames.Code() != "01_02" {
		return fmt.Errorf("réponse inattendue à la poignée de main : %s", trames.Code())
	}

	// Comparaison sur les OCTETS du contenu, sans TrimSpace : le défi est de
	// l'aléa brut et peut parfaitement commencer ou finir par un octet
	// d'espacement. Le rogner rendrait la comparaison fausse une fois sur
	// quelques dizaines — une panne intermittente introuvable.
	if !bytes.Equal(challenge, []byte(trames.Content)) {
		return ErrServerNotAuthentic
	}

	session.SessionID = trames.SessionIntegritykey
	session.SessionKey = NormalizeSessionKey(trames.SessionIntegritykey)
	session.IsSafe = true
	logs.Write("INFO", "serveur authentifié, session chiffrée établie")
	return nil
}

// NormalizeSessionKey ramène la clé de session à 32 octets.
//
// Le core la produit sur 32 caractères hexadécimaux, utilisés TELS QUELS comme
// clé AES-256 — ce sont les 32 octets ASCII, pas les 16 octets qu'ils
// représentent. Ne pas les décoder est donc voulu, et décoder casserait le
// tunnel. Le complément à zéro n'existe que pour ne pas paniquer face à une
// version qui en enverrait moins.
func NormalizeSessionKey(s string) []byte {
	key := []byte(s)
	if len(key) == 32 {
		return key
	}
	out := make([]byte, 32)
	copy(out, key)
	return out
}

// Handler est le gestionnaire par défaut de la catégorie 01.
//
// En régime établi, les trames 01 arrivent en réponse à ce que nous avons
// envoyé, dans le flot de Handshake : elles ne repassent donc pas par le
// Spliter. Ce gestionnaire existe pour que le comportement soit défini plutôt
// que silencieux.
func Handler(trames storage.Trames_struct_client, session *storage.DuckySession) string {
	switch trames.Code() {
	case "01_05", "01_06":
		logs.Write("ERROR", "enrôlement refusé par le core : "+firstLine(trames.Content))
	default:
		logs.Write("DEBUG", "trame 01 non sollicitée ignorée : "+trames.Code())
	}
	return ""
}
