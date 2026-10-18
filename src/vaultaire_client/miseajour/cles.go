package miseajour

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/enligne"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"

	"vaultaire_client/pamstate"
	"vaultaire_client/paquet"
)

// Le jeu de clés de confiance des paquets — TO-DO 207.
//
// L'agent tient le fichier pkg_signing_key.pem, déposé à l'installation, et
// son numéro. Il demande au core le jeu qui suit (09_09, avec son numéro) à
// chaque session neuve et toutes les heures ; le core répond le plus petit
// jeu au-dessus (09_10), ou « a_jour ». Un jeu n'est appliqué que signé par
// une clé que la machine tient DÉJÀ, et plus haut que le sien : un core, un
// proxy ou un réseau ne peuvent rien y ajouter sans cette clé. Après un jeu
// appliqué, la réponse EST la demande suivante : la machine remonte la chaîne
// d'une rotation entière en quelques échanges, et déclare son nouveau numéro.
//
// Une clé compromise ne se remplace PAS par ce canal (voir le core,
// --pkg-key compromised) : son jeu est signé par une clé que la machine ne
// tient pas, et il est refusé ici — journalisé, la machine est à réinstaller.

// IntervalleJeuCles : sans session neuve, une demande par heure — une machine
// connectée des semaines suit quand même une rotation.
var IntervalleJeuCles = time.Hour

// coreSaitCles : la 09_09 n'est émise que vers un core qui annonce la
// capacité. Remplaçable par les tests.
var coreSaitCles = func() bool { return enligne.CoreSait(enligne.CapaciteClesPaquets) }

// numeroLocal et appliquerJeu : remplaçables par les tests.
var (
	numeroLocal  = paquet.NumeroDuJeu
	appliquerJeu = paquet.AppliquerJeu
)

// DemandeJeu compose la 09_09 : le numéro du jeu que la machine tient.
func DemandeJeu(sessionKey string) string {
	return strings.Join([]string{"09_09", "serveur_central", sessionKey, pamstate.Username,
		storage.Computeur_ID, strconv.Itoa(numeroLocal())}, "\n")
}

// recevoirJeu traite une 09_10, et rend la demande suivante — ou rien.
func recevoirJeu(t storage.Trames_struct_client) string {
	l := strings.Split(strings.TrimRight(strings.ReplaceAll(t.Content, "\r", ""), "\n"), "\n")
	if len(l) == 1 && strings.TrimSpace(l[0]) == "a_jour" {
		logs.Write_log("DEBUG", fmt.Sprintf("clés des paquets : jeu n°%d, à jour", numeroLocal()))
		return ""
	}
	if len(l) != 3 {
		logs.Write_log("WARNING", "clés des paquets : réponse 09_10 illisible")
		return ""
	}
	corps, err1 := base64.StdEncoding.DecodeString(strings.TrimSpace(l[1]))
	brute, err2 := base64.StdEncoding.DecodeString(strings.TrimSpace(l[2]))
	if err1 != nil || err2 != nil {
		logs.Write_log("WARNING", "clés des paquets : réponse 09_10 illisible (base64)")
		return ""
	}
	env, err := paquet.LireEnveloppe(string(brute))
	if err != nil {
		logs.Write_log("WARNING", "clés des paquets : "+err.Error())
		return ""
	}
	avant := numeroLocal()
	j, err := appliquerJeu(string(corps), env)
	if err != nil {
		// Signé par une clé inconnue : une compromission traitée hors bande,
		// ou quelqu'un qui essaie. Dans les deux cas, à voir.
		logs.Write_log("SECURITY", fmt.Sprintf("clés des paquets : jeu n°%s REFUSÉ (la machine tient le n°%d) — %v",
			strings.TrimSpace(l[0]), avant, err))
		return ""
	}
	var empreintes []string
	for _, c := range j.Cles {
		e, _ := paquet.EmpreinteCle(c)
		empreintes = append(empreintes, e)
	}
	logs.Write_log("SECURITY", fmt.Sprintf("clés des paquets : jeu n°%d appliqué (avant : n°%d) — clés de confiance : %s",
		j.Numero, avant, strings.Join(empreintes, ", ")))
	return DemandeJeu(t.SessionIntegritykey)
}

// suiviJeu décide quand demander : à chaque clé de session neuve, et après
// IntervalleJeuCles sans demande.
type suiviJeu struct {
	derniereCle string
	derniere    time.Time
}

func (s *suiviJeu) doitDemander(cle string, sait bool, maintenant time.Time) bool {
	if cle == "" || !sait {
		return false
	}
	return cle != s.derniereCle || maintenant.Sub(s.derniere) >= IntervalleJeuCles
}

// SurveillerLesCles demande le jeu suivant. Ne rend jamais la main.
func SurveillerLesCles(cleDeSession func() string) {
	var s suiviJeu
	for {
		cle := cleDeSession()
		if maintenant := time.Now(); s.doitDemander(cle, coreSaitCles(), maintenant) {
			if emettre(DemandeJeu(cle)) {
				s.derniereCle, s.derniere = cle, maintenant
			}
		}
		time.Sleep(5 * time.Second)
	}
}
