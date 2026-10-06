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
	// 02_11 toutes les `check_online_minutes` (2 par défaut) ; dix minutes
	// laissent donc passer quatre battements manqués avant de couper.
	//
	// C'est un PLANCHER pour le réseau Ducky, pas sa valeur : à cadence longue
	// il emploie ArmReadDeadlineFor avec une échéance calculée (TO-DO 110).
	SessionReadTimeout = 10 * time.Minute
)

// ArmReadDeadline pose le délai de lecture correspondant à l'état de la session.
//
// À appeler AVANT chaque lecture bloquante : un délai est absolu, pas glissant.
// Le poser une seule fois à l'ouverture couperait la connexion à échéance, même
// active — c'est l'erreur classique avec SetReadDeadline.
func ArmReadDeadline(conn net.Conn, authentifiee bool) {
	délai := HandshakeReadTimeout
	if authentifiee {
		délai = SessionReadTimeout
	}
	ArmReadDeadlineFor(conn, délai)
}

// ArmReadDeadlineFor pose un délai de lecture CHOISI par l'appelant.
//
// # Pourquoi l'appelant choisit (TO-DO 110)
//
// SessionReadTimeout est une constante : dix minutes, « plusieurs cycles de
// battement » à la cadence par défaut de deux. Or la cadence du battement Ducky
// se règle jusqu'à soixante minutes. À onze, cette échéance tombait ENTRE deux
// battements : le core coupait lui-même, toutes les dix minutes, chaque
// session du parc — alors même que le balayage, lui, avait appris à suivre le
// réglage.
//
// Le réseau Ducky calcule donc son échéance (voir duckynetwork) et la passe
// ici. LDAP garde ArmReadDeadline : rien n'y bat, aucune cadence ne le concerne.
//
// Ce paquet ne lit pas le réglage lui-même : il est sous `reglages` dans
// l'arbre des dépendances, et doit y rester.
func ArmReadDeadlineFor(conn net.Conn, délai time.Duration) {
	if conn == nil {
		return
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
