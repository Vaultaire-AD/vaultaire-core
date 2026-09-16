package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Paramètres argon2id.
//
// Ce sont les valeurs planchers recommandées par l'OWASP : 19 Mio de mémoire,
// deux passes, un fil. Environ 30 à 50 ms par vérification sur un serveur
// ordinaire.
//
// La MÉMOIRE est le paramètre qui compte, pas le nombre de passes. Un GPU essaie
// des milliards de SHA-256 par seconde parce qu'un SHA-256 ne coûte rien en
// mémoire : on en fait tourner des milliers en parallèle sur une seule carte.
// Exiger 19 Mio par tentative divise ce parallélisme par le rapport entre la
// mémoire de la carte et 19 Mio — quelques centaines au lieu de quelques
// milliers de fils. C'est là que se joue la résistance à une base volée.
//
// Le revers est côté serveur : 19 Mio × nombre d'authentifications EN COURS.
// Une rafale de cent connexions simultanées demande environ 2 Gio de pointe.
// C'est ce qui borne la valeur vers le haut, pas le temps de calcul.
const (
	ArgonMemoireKio uint32 = 19 * 1024 // 19 Mio
	ArgonTours      uint32 = 2
	ArgonFils       uint8  = 1
	ArgonLongueur   uint32 = 32
	ArgonSelOctets         = 16
)

// prefixeArgon2id ouvre toute empreinte au format PHC.
//
// C'est aussi ce qui permet de distinguer les deux formats SANS colonne
// supplémentaire : une empreinte SHA-256 héritée est 64 caractères
// hexadécimaux, elle ne peut pas commencer par « $ ».
const prefixeArgon2id = "$argon2id$"

// Hacher produit l'empreinte à stocker et le sel qui l'accompagne.
//
// L'empreinte rendue est une chaîne PHC complète :
//
//	$argon2id$v=19$m=19456,t=2,p=1$<sel base64>$<empreinte base64>
//
// # Pourquoi le format se décrit lui-même
//
// Une colonne « algorithme » aurait suffi à distinguer les deux formats, mais
// pas à relire une empreinte argon2id : il faut aussi les PARAMÈTRES qui ont
// servi à la produire. Le jour où 19 Mio ne suffiront plus, les empreintes déjà
// en base auront été calculées avec l'ancienne valeur, et une colonne qui ne
// porte que « argon2id » ne dira pas laquelle.
//
// Les porter dans l'empreinte règle les deux questions d'un coup, et évite une
// migration de schéma — donc évite qu'une installation existante se retrouve
// avec du code qui lit une colonne absente.
//
// Le sel est rendu séparément, en hexadécimal, pour la colonne `salt` : elle est
// NOT NULL, les comptes hérités s'en servent, et la garder cohérente coûte
// moins cher que de la faire disparaître. Pour une empreinte argon2id, c'est
// celui embarqué dans la chaîne PHC qui fait foi.
func Hacher(motDePasse string) (empreinte string, selHex string, err error) {
	sel := make([]byte, ArgonSelOctets)
	if _, err := rand.Read(sel); err != nil {
		return "", "", fmt.Errorf("génération du sel impossible : %w", err)
	}
	return HacherAvecSel(motDePasse, sel), hex.EncodeToString(sel), nil
}

// HacherAvecSel est la partie déterministe de Hacher, isolée pour les tests.
func HacherAvecSel(motDePasse string, sel []byte) string {
	return construirePHC(motDePasse, sel, ArgonMemoireKio, ArgonTours, ArgonFils)
}

// construirePHC assemble la chaîne avec des paramètres DONNÉS.
//
// Les paramètres sont des arguments et non les constantes du paquet pour une
// raison précise : les tests doivent pouvoir fabriquer une empreinte calculée
// avec des réglages plus faibles — ou plus forts — que ceux du jour. Sans cela,
// la règle de réencodage ne serait éprouvée que sur le cas où elle ne s'applique
// pas.
func construirePHC(motDePasse string, sel []byte, memoire, tours uint32, fils uint8) string {
	somme := argon2.IDKey([]byte(motDePasse), sel, tours, memoire, fils, ArgonLongueur)
	return fmt.Sprintf("%sv=%d$m=%d,t=%d,p=%d$%s$%s",
		prefixeArgon2id, argon2.Version,
		memoire, tours, fils,
		base64.RawStdEncoding.EncodeToString(sel),
		base64.RawStdEncoding.EncodeToString(somme))
}

// Verifier contrôle un mot de passe et dit s'il faut réencoder l'empreinte.
//
// `aReencoder` vaut vrai quand le mot de passe est BON mais que l'empreinte
// stockée n'est pas celle qu'on produirait aujourd'hui — empreinte SHA-256
// héritée, ou argon2id calculée avec des paramètres plus faibles.
//
// # Pourquoi la migration ne peut pas se faire autrement
//
// On ne peut pas recalculer une empreinte forte à partir d'une faible : le mot
// de passe n'existe nulle part. Le seul instant où il est disponible est la
// connexion réussie. Une campagne de migration est donc impossible ; la seule
// voie est de réencoder au fil des connexions, et d'accepter que les comptes
// dormants restent en SHA-256 jusqu'à leur retour.
//
// C'est aussi pourquoi la lecture des empreintes héritées ne peut pas être
// retirée à une date fixée d'avance : le faire enfermerait dehors tout compte
// qui ne s'est pas connecté d'ici là.
//
// Fail-closed : une empreinte qui n'est ni une chaîne PHC argon2id ni un
// SHA-256 hexadécimal est refusée, elle n'est pas devinée.
func Verifier(motDePasse, selHex, empreinte string) (valide bool, aReencoder bool) {
	if strings.HasPrefix(empreinte, prefixeArgon2id) {
		return verifierArgon2id(motDePasse, empreinte)
	}
	if verifierHerite(motDePasse, selHex, empreinte) {
		return true, true
	}
	return false, false
}

// verifierHerite relit une empreinte SHA-256 du format d'origine.
//
// Conservée pour une seule raison : les comptes créés avant la bascule. Elle
// disparaîtra quand plus aucune ligne ne portera ce format — ce qu'une requête
// suffit à savoir, l'empreinte se décrivant elle-même.
//
// La comparaison passe par subtle.ConstantTimeCompare, là où l'ancienne version
// utilisait « == » sur des chaînes. La comparaison de chaînes de Go s'arrête au
// premier octet qui diffère : le temps de réponse renseigne alors sur le nombre
// de caractères devinés, et permet de reconstruire l'empreinte octet par octet
// sans jamais la connaître. Exploiter cela à travers le réseau est difficile,
// mais l'écart de coût entre les deux écritures est nul.
func verifierHerite(motDePasse, selHex, empreinteHex string) bool {
	sel, err := hex.DecodeString(selHex)
	if err != nil {
		return false
	}
	attendue, err := hex.DecodeString(empreinteHex)
	if err != nil || len(attendue) != sha256.Size {
		return false
	}
	sale := append(append([]byte{}, sel...), []byte(motDePasse)...)
	somme := sha256.Sum256(sale)
	return subtle.ConstantTimeCompare(somme[:], attendue) == 1
}

// verifierArgon2id relit une chaîne PHC et recalcule avec SES paramètres.
//
// Recalculer avec les paramètres COURANTS donnerait un résultat différent de
// celui stocké et refuserait un mot de passe correct — c'est précisément ce que
// l'auto-description évite.
func verifierArgon2id(motDePasse, empreinte string) (valide bool, aReencoder bool) {
	parts := strings.Split(empreinte, "$")
	// "" / "argon2id" / "v=19" / "m=...,t=...,p=..." / sel / empreinte
	if len(parts) != 6 {
		return false, false
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false
	}

	var memoire, tours uint32
	var fils uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memoire, &tours, &fils); err != nil {
		return false, false
	}
	if memoire == 0 || tours == 0 || fils == 0 {
		return false, false
	}

	sel, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(sel) == 0 {
		return false, false
	}
	attendue, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(attendue) == 0 {
		return false, false
	}

	somme := argon2.IDKey([]byte(motDePasse), sel, tours, memoire, fils, uint32(len(attendue)))
	if subtle.ConstantTimeCompare(somme, attendue) != 1 {
		return false, false
	}

	// Réencoder dès qu'un paramètre est SOUS la valeur courante, jamais quand il
	// est au-dessus : une empreinte calculée plus fortement que le réglage du
	// jour ne doit pas être affaiblie par un simple passage de connexion.
	affaiblie := memoire < ArgonMemoireKio || tours < ArgonTours || fils < ArgonFils
	return true, affaiblie
}

// ComparePasswords a été SUPPRIMÉE. Utiliser dbusers.VerifierMotDePasse.
//
// Elle rendait un simple booléen, donc taisait le besoin de réencodage. La
// garder « au cas où » aurait suffi à ce que la migration s'arrête : le
// prochain chemin d'authentification écrit l'aurait trouvée, elle aurait fait
// exactement ce qu'on attend d'elle, et les comptes passant par là seraient
// restés en SHA-256 sans que rien ne le signale.
//
// Une fonction dont le seul défaut est de ne pas faire assez est plus
// dangereuse qu'une fonction absente : la seconde ne compile pas.
