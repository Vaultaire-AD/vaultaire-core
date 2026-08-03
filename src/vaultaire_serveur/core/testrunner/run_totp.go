package testrunner

import (
	"fmt"
	"strings"
	"time"

	"vaultaire/core/global/security/totp"
)

// Tests de l'implémentation TOTP.
//
// La suite repose sur les VECTEURS DE TEST DE LA RFC 6238, annexe B. C'est ce
// qui distingue « mon code produit des chiffres » de « mon code produit les
// bons chiffres » : une erreur d'offset dans la troncature dynamique, ou un
// entier lu en petit-boutiste, donne un générateur parfaitement cohérent avec
// lui-même — le serveur validerait ses propres codes — mais incompatible avec
// toutes les applications d'authentification du marché. Le bogue ne serait
// visible qu'au premier utilisateur qui scanne un QR code.
//
// Les vecteurs sont publiés sur 8 chiffres, alors que l'implémentation en
// produit 6. Les 6 chiffres attendus sont les 6 DERNIERS des 8 : la troncature
// est un modulo, donc réduire le nombre de chiffres revient à prendre le reste
// modulo une puissance de dix plus petite. Tester ainsi valide la partie du
// calcul qui compte — HMAC, offset, extraction 31 bits — sans avoir à rendre
// configurable une longueur qui ne le sera jamais.
func testTOTP() []Result {
	var out []Result

	// Le secret des vecteurs RFC est la chaîne ASCII « 12345678901234567890 »,
	// que les tables publient sous forme hexadécimale. Encodée en base32, sans
	// remplissage, c'est ce que l'implémentation attend.
	const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	vectors := []struct {
		unixTime int64
		expect8  string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	allOK := true
	for _, v := range vectors {
		counter := totp.CounterAt(time.Unix(v.unixTime, 0))
		got, err := totp.Code(rfcSecret, counter)
		want := v.expect8[len(v.expect8)-totp.Digits:]
		if err != nil || got != want {
			allOK = false
			out = append(out, Result{
				fmt.Sprintf("TOTP: vecteur RFC 6238 T=%d", v.unixTime), false,
				fmt.Sprintf("attendu %s, obtenu %q (err=%v)", want, got, err)})
		}
	}
	if allOK {
		out = append(out, Result{"TOTP: 6 vecteurs RFC 6238 conformes", true, ""})
	}

	// Fenêtre de tolérance : le pas courant, le précédent et le suivant sont
	// acceptés, le pas au-delà ne l'est pas. Sans cette borne, un code resterait
	// valide bien après son affichage.
	now := time.Unix(1111111111, 0)
	current := totp.CounterAt(now)
	windowOK := true
	for delta := -totp.SkewSteps; delta <= totp.SkewSteps; delta++ {
		code, err := totp.Code(rfcSecret, current+int64(delta))
		if err != nil {
			windowOK = false
			break
		}
		if _, ok := totp.Validate(rfcSecret, code, now); !ok {
			windowOK = false
		}
	}
	out = append(out, Result{"TOTP: la fenêtre de tolérance accepte ±1 pas", windowOK,
		"un code de la fenêtre est refusé"})

	outsideOK := true
	for _, delta := range []int64{-(totp.SkewSteps + 1), totp.SkewSteps + 1} {
		code, err := totp.Code(rfcSecret, current+delta)
		if err != nil {
			outsideOK = false
			break
		}
		if _, ok := totp.Validate(rfcSecret, code, now); ok {
			outsideOK = false
		}
	}
	out = append(out, Result{"TOTP: un code hors fenêtre est refusé", outsideOK,
		"un code trop ancien ou trop lointain est accepté"})

	// Le pas retourné doit être celui du code, pas celui de l'instant courant :
	// c'est lui qui part dans l'anti-rejeu, et le confondre avec l'instant
	// courant laisserait rejouer le code du pas précédent.
	prevCode, _ := totp.Code(rfcSecret, current-1)
	gotCounter, ok := totp.Validate(rfcSecret, prevCode, now)
	out = append(out, Result{"TOTP: le pas retourné est celui du code validé",
		ok && gotCounter == current-1,
		fmt.Sprintf("attendu %d, obtenu %d (ok=%v)", current-1, gotCounter, ok)})

	// Entrées malformées. Aucune ne doit valider, et aucune ne doit paniquer —
	// ces chaînes viennent d'un formulaire web.
	badOK := true
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "12 34 5", "٠١٢٣٤٥"} {
		if _, ok := totp.Validate(rfcSecret, bad, now); ok {
			badOK = false
		}
	}
	out = append(out, Result{"TOTP: les codes malformés sont refusés", badOK,
		"une entrée invalide est acceptée"})

	// Un code coupé en deux groupes de trois par l'application doit passer :
	// c'est ce que l'utilisateur colle depuis son écran.
	spacedCode, _ := totp.Code(rfcSecret, current)
	spaced := spacedCode[:3] + " " + spacedCode[3:]
	_, spacedOK := totp.Validate(rfcSecret, spaced, now)
	out = append(out, Result{"TOTP: un code collé avec une espace est accepté", spacedOK,
		"l'espace de séparation fait échouer la validation"})

	// Un secret vide ou illisible ne doit jamais valider. Un compte dont le
	// secret aurait été effacé en base se retrouverait sinon protégé par un
	// second facteur que n'importe quel code satisfait.
	_, emptyOK := totp.Validate("", "000000", now)
	_, junkOK := totp.Validate("pas-du-base32-!!", "000000", now)
	out = append(out, Result{"TOTP: un secret vide ou illisible ne valide rien",
		!emptyOK && !junkOK, "un secret invalide accepte un code"})

	// Deux secrets tirés d'affilée doivent différer, et faire la bonne longueur.
	s1, err1 := totp.GenerateSecret()
	s2, err2 := totp.GenerateSecret()
	out = append(out, Result{"TOTP: les secrets générés sont distincts et de bonne taille",
		err1 == nil && err2 == nil && s1 != s2 && len(s1) == 32 && !strings.Contains(s1, "="),
		fmt.Sprintf("s1=%q s2=%q", s1, s2)})

	// L'URL de provisionnement doit porter l'émetteur aux deux endroits attendus
	// par les applications, et ne pas contenir de remplissage base32.
	uri := totp.ProvisioningURI("Vaultaire", "alice@vaultaire.fr", rfcSecret)
	uriOK := strings.HasPrefix(uri, "otpauth://totp/") &&
		strings.Contains(uri, "issuer=Vaultaire") &&
		strings.Contains(uri, "secret="+rfcSecret) &&
		strings.Contains(uri, "Vaultaire%3Aalice") &&
		!strings.Contains(uri, "%3D")
	out = append(out, Result{"TOTP: l'URL otpauth est bien formée", uriOK, uri})

	return out
}
