package dbusers_test

import (
	"strconv"
	"strings"
	"testing"

	dbusers "vaultaire/core/database/db_users"
	keydecodeencode "vaultaire/ducky-network/key_decode_encode"
	"vaultaire/ducky-network/sendmessage"
)

// TestLesClesDUnCompteTiennentDansUneTrame lie les deux bornes de AddUserKey à
// la taille maximale d'une trame Ducky (TO-DO 101).
//
// La trame 02_04 porte TOUTES les clés du compte, jointes par des virgules, à
// chaque authentification Ducky. Si elle dépassait 65535 octets une fois
// chiffrée, elle ne partirait plus et le compte ne pourrait plus ouvrir de
// session sur aucun poste. Relever MaxClesParCompte ou LongueurMaxCle sans
// refaire ce calcul fait échouer ce test, et c'est voulu.
//
// Le pire cas est construit comme CheckAuthentification construit la vraie
// trame, avec un nom d'utilisateur et une clé d'intégrité très longs, puis
// chiffré en AES-GCM et encodé en base64 comme SendMessage le fait sur une
// session établie.
func TestLesClesDUnCompteTiennentDansUneTrame(t *testing.T) {
	cles := make([]string, dbusers.MaxClesParCompte)
	for i := range cles {
		cles[i] = strings.Repeat("k", dbusers.LongueurMaxCle)
	}
	utilisateur := strings.Repeat("u", 255) + "@" + strings.Repeat("d", 255)
	integrite := strings.Repeat("s", 128)

	trame := "02_04\nserveur_central\n" + integrite + "\n" + utilisateur + "\n" +
		strconv.FormatBool(true) + "\n" + strings.Join(cles, ",") +
		"\nYou are authentificate Has : \n" + utilisateur

	cleAES := make([]byte, 32)
	chiffre, err := keydecodeencode.EncryptAESGCMString(cleAES, trame)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sendmessage.CompileMessageSize([]byte(chiffre)); err != nil {
		t.Fatalf("%d clés de %d caractères ne tiennent plus dans une trame 02_04 (%d octets chiffrés) : "+
			"un compte à la limite ne pourrait plus se connecter. Abaisser l'une des bornes. %v",
			dbusers.MaxClesParCompte, dbusers.LongueurMaxCle, len(chiffre), err)
	}
	t.Logf("pire cas : %d octets chiffrés sur %d", len(chiffre), sendmessage.TailleMaxCorps)
}
