// Package totp implémente les mots de passe à usage unique fondés sur le temps,
// RFC 6238, au-dessus de HOTP, RFC 4226.
//
// POURQUOI PAS UNE BIBLIOTHÈQUE. L'algorithme tient en trente lignes et n'a pas
// bougé depuis 2011 : un compteur de 8 octets, un HMAC, une troncature
// dynamique, un modulo. Tout est dans la bibliothèque standard de Go. Une
// dépendance externe ajouterait une surface d'approvisionnement à un projet qui
// en compte dix, pour du code qui ne changera plus.
//
// POURQUOI SHA-1, en 2026. Les applications d'authentification — Google
// Authenticator, Aegis, FreeOTP, 1Password, Bitwarden — ignorent en pratique le
// paramètre `algorithm` de l'URL otpauth:// et supposent SHA-1. Publier SHA-256
// donnerait des codes refusés sur la moitié du parc, sans message
// compréhensible. Ce n'est d'ailleurs pas un problème ici : HMAC-SHA1 n'est pas
// affaibli par les collisions de SHA-1, qui ne portent pas sur les MAC à clé, et
// le secret est de toute façon renouvelable.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// SecretBytes est la taille du secret partagé.
	//
	// 20 octets, soit 160 bits : c'est la taille de bloc de HMAC-SHA1 et ce que
	// recommande la RFC 4226 §4. Au-delà, HMAC replierait la clé par hachage
	// sans rien apporter ; en deçà, on affaiblirait sans gagner de place.
	SecretBytes = 20

	// PeriodSeconds est la durée de vie d'un code.
	//
	// 30 secondes, valeur par défaut de la RFC et seule que les applications
	// d'authentification affichent correctement sans configuration.
	PeriodSeconds = 30

	// Digits est la longueur d'un code.
	Digits = 6

	// SkewSteps est la tolérance, en pas de temps, de part et d'autre du pas
	// courant.
	//
	// Un pas accepte donc le code précédent et le suivant, soit 90 secondes de
	// fenêtre totale. C'est ce qui absorbe une horloge de téléphone décalée de
	// quelques secondes et le temps de saisie de l'utilisateur. Monter au-delà
	// élargirait la fenêtre de rejeu sans résoudre un décalage plus grave, qui
	// relève du réglage de l'horloge et non de la tolérance du serveur.
	SkewSteps = 1
)

// base32NoPadding est l'encodage attendu par les applications
// d'authentification.
//
// Sans caractère de remplissage : les 20 octets du secret donnent 32 caractères
// base32 sans reste, et un `=` final dans une URL otpauth:// fait échouer
// plusieurs lecteurs de QR code.
var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret produit un nouveau secret partagé, encodé en base32.
//
// L'erreur de crypto/rand est remontée et jamais ignorée. Un secret produit à
// partir d'une source d'entropie en échec serait prévisible, donc pire
// qu'absent : l'utilisateur croirait son compte protégé par un second facteur.
func GenerateSecret() (string, error) {
	buf := make([]byte, SecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("génération du secret TOTP : %w", err)
	}
	return base32NoPadding.EncodeToString(buf), nil
}

// CounterAt retourne le pas de temps correspondant à un instant.
//
// Exposé parce que l'anti-rejeu se fait sur ce pas et non sur le code : deux
// codes identiques à des pas différents doivent être distingués, et c'est le pas
// qui est stocké en base.
func CounterAt(t time.Time) int64 {
	return t.Unix() / PeriodSeconds
}

// Code calcule le code d'un pas de temps donné.
func Code(secret string, counter int64) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Troncature dynamique, RFC 4226 §5.3 : les 4 bits de poids faible du
	// dernier octet désignent l'offset des 4 octets à extraire. Le masque
	// 0x7f sur le premier de ces octets écarte le bit de signe, pour que le
	// résultat soit identique quelle que soit la façon dont le langage
	// interprète un entier signé.
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", Digits, value%mod), nil
}

// Validate vérifie un code et retourne le pas de temps qu'il consomme.
//
// Le pas retourné doit être passé à l'anti-rejeu par l'appelant : cette fonction
// ne connaît pas la base et ne peut donc pas empêcher, à elle seule, qu'un code
// intercepté soit rejoué pendant sa fenêtre de validité. C'est délibéré — la
// règle cryptographique et la mémoire de ce qui a été consommé sont deux
// responsabilités distinctes, et seule la seconde a besoin d'un stockage.
//
// La comparaison est faite en temps constant. Le gain est mince sur six chiffres
// — un attaquant a mieux à faire que de mesurer des microsecondes pour deviner
// un code qui expire en trente secondes — mais une comparaison de chaînes par
// `==` dans du code d'authentification finit toujours par être recopiée
// ailleurs, sur un secret où la fuite compterait.
func Validate(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	// Certaines applications affichent le code en deux groupes de trois. Coller
	// depuis l'écran ramène donc parfois une espace au milieu.
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != Digits {
		return 0, false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false
		}
	}

	current := CounterAt(now)
	// La boucle parcourt TOUS les pas de la fenêtre, même après avoir trouvé une
	// correspondance : sortir dès le premier succès rendrait la durée de la
	// fonction dépendante de la position du code dans la fenêtre.
	matched := false
	var matchedCounter int64
	for delta := -SkewSteps; delta <= SkewSteps; delta++ {
		counter := current + int64(delta)
		expected, err := Code(secret, counter)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			matched = true
			matchedCounter = counter
		}
	}
	return matchedCounter, matched
}

// decodeSecret relit un secret base32.
//
// Tolère la casse et les espaces : un secret recopié à la main depuis l'écran
// arrive souvent en minuscules ou groupé par blocs de quatre.
func decodeSecret(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	cleaned = strings.TrimRight(cleaned, "=")
	if cleaned == "" {
		return nil, fmt.Errorf("secret TOTP vide")
	}
	key, err := base32NoPadding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("secret TOTP illisible : %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("secret TOTP vide après décodage")
	}
	return key, nil
}

// ProvisioningURI construit l'URL otpauth:// à présenter en QR code.
//
// Format : otpauth://totp/Émetteur:compte?secret=…&issuer=…
//
// L'émetteur apparaît DEUX FOIS, dans le label et en paramètre. C'est
// redondant et c'est voulu : les applications anciennes ne lisent que le
// préfixe du label, les récentes préfèrent le paramètre. N'en mettre qu'un
// donne, selon l'application, une entrée sans nom ou un doublon indistinct
// quand l'utilisateur gère plusieurs annuaires.
//
// url.PathEscape et non QueryEscape sur le label : QueryEscape encode l'espace
// en `+`, ce qui s'affiche littéralement dans le nom du compte.
func ProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)

	params := url.Values{}
	params.Set("secret", strings.ToUpper(strings.TrimSpace(secret)))
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", fmt.Sprint(Digits))
	params.Set("period", fmt.Sprint(PeriodSeconds))

	return "otpauth://totp/" + label + "?" + params.Encode()
}

// FormatSecretForDisplay coupe le secret en groupes de quatre caractères.
//
// Pour la saisie manuelle, quand la caméra ne lit pas le QR code : trente-deux
// caractères d'affilée se recopient mal, et une erreur de saisie ne se
// distingue pas d'un problème d'horloge au moment de la vérification.
func FormatSecretForDisplay(secret string) string {
	s := strings.ToUpper(strings.TrimSpace(secret))
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}
