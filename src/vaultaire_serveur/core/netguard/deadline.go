package netguard

import (
	"net"
	"time"
)

// Délais de lecture.
//
// # Pourquoi un délai EN PLUS du balayage périodique
//
// Le balayage ferme déjà les sessions inactives, et fermer le socket débloque la
// lecture en cours. Mais il tourne toutes les deux minutes : entre deux
// passages, une connexion muette garde sa goroutine et son descripteur.
//
// Le délai de lecture borne cela à la seconde près, sans dépendre d'un ticker.
// Les deux se complètent : le délai coupe le socket bloqué, le balayage retire
// l'entrée du registre.
//
// # Pourquoi deux valeurs
//
// Avant authentification, un client réel enchaîne sa poignée de main en une
// fraction de seconde ; une minute est déjà très généreuse. Après, une session
// légitime peut rester silencieuse entre deux battements de cœur, et la couper
// serait une régression visible.
var (
	// HandshakeReadTimeout borne l'attente AVANT authentification.
	//
	// # Ne pas descendre sous 30 secondes sans mesurer
	//
	// L'enrôlement d'un service passe par ici, et le client génère sa paire
	// RSA-4096 ENTRE deux trames — donc pendant que le serveur attend. Mesuré sur
	// douze tirages : 536 ms en moyenne, 1,56 s au pire. La génération RSA est
	// probabiliste, sa durée varie fortement d'un tirage à l'autre, et un
	// appareil peu puissant peut être dix fois plus lent.
	//
	// Soixante secondes laissent donc une marge d'environ quarante fois le pire
	// cas observé. C'est ce qui rend le délai sûr pour l'enrôlement tout en
	// restant serré face à une connexion muette.
	HandshakeReadTimeout = 60 * time.Second

	// SessionReadTimeout borne l'attente APRÈS authentification.
	//
	// Doit couvrir plusieurs cycles de battement de cœur. Le serveur envoie un
	// 02_11 toutes les ServerCheckOnlineTimer minutes (2 par défaut) ; dix
	// minutes laissent donc passer quatre battements manqués avant de couper.
	SessionReadTimeout = 10 * time.Minute
)

// ArmReadDeadline pose le délai de lecture correspondant à l'état de la session.
//
// À appeler AVANT chaque lecture bloquante : un délai est absolu, pas glissant.
// Le poser une seule fois à l'ouverture couperait la connexion à échéance, même
// active — c'est l'erreur classique avec SetReadDeadline.
func ArmReadDeadline(conn net.Conn, authentifiee bool) {
	if conn == nil {
		return
	}
	délai := HandshakeReadTimeout
	if authentifiee {
		délai = SessionReadTimeout
	}
	if délai <= 0 {
		// Zéro désactive : SetReadDeadline(time.Time{}) retire le délai.
		_ = conn.SetReadDeadline(time.Time{})
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(délai))
}

// ClearReadDeadline retire le délai.
//
// Utile autour d'un traitement long et légitime, pour ne pas qu'il compte dans
// le temps d'attente de la lecture suivante.
func ClearReadDeadline(conn net.Conn) {
	if conn != nil {
		_ = conn.SetReadDeadline(time.Time{})
	}
}
