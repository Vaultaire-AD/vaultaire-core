package dbsessions

import (
	"time"

	"vaultaire/core/reglages"
)

// Durée de vie d'une ligne de session — `did_login` comme `user_sessions`.
//
// # Une constante, parce qu'il y en avait trois
//
// `10 * time.Minute` était écrit dans AddLoginEntry, RafraichirConnexion et
// RefreshSessionValidity. Trois copies d'un même nombre, dans trois fichiers
// qu'on ne modifie jamais ensemble : allonger la validité d'un côté aurait
// donné des sessions qui expirent ou non selon le chemin qui les a écrites,
// c'est-à-dire un comportement qu'on ne peut pas expliquer en lisant un seul
// fichier.
//
// # Pourquoi dix minutes, et pas plus
//
// C'est une SURVIE SANS NOUVELLE, pas une durée de session. Une machine qui
// bat toutes les deux minutes (`check_online_minutes`) repousse l'échéance
// bien avant qu'elle n'arrive ; dix minutes, c'est ce qu'on accepte d'afficher
// comme « connecté » une machine qui, en réalité, a été débranchée.
//
// # Pourquoi ce n'est plus une constante (TO-DO 110)
//
// Dix minutes valaient pour une cadence de deux. Le réglage monte à soixante :
// à onze minutes, chaque ligne expirait entre deux battements, et la purge
// retirait de `status -c` un parc entier de machines connectées. La durée est
// maintenant calculée depuis le réglage — la tolérance de silence du balayage
// plus une cadence, dix minutes au moins — par reglages.ValiditeDeSession, qui
// dit pourquoi.
func ValiditeSession() time.Duration { return reglages.ValiditeDeSession() }

// EcheanceSession rend l'horodatage d'expiration à écrire en base.
//
// Le format est celui des trois fonctions d'origine : MySQL l'accepte pour un
// TIMESTAMP, et le changer ferait échouer des écritures sans rien apporter.
func EcheanceSession() string {
	return time.Now().Add(ValiditeSession()).Format("2006/01/02 15:04:05")
}
