package ratelimit

import (
	"net/http"
	"testing"
)

func requete(remote, xff string) *http.Request {
	r := &http.Request{
		RemoteAddr: remote,
		Header:     http.Header{},
	}
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

// TestXFFIgnoreSansProxyDeclare : sans relais déclaré, l'en-tête ne vaut rien.
//
// C'est LE test qui compte. Croire X-Forwarded-For parce qu'il est présent est
// pire que de ne rien limiter : il est écrit par le client, donc une valeur
// différente à chaque tentative donne un compteur neuf à chaque coup.
func TestXFFIgnoreSansProxyDeclare(t *testing.T) {
	ProxiesDeConfiance = nil

	got := SourceHTTP(requete("203.0.113.9:51000", "1.2.3.4"))
	if got != "203.0.113.9" {
		t.Errorf("source = %q, attendue %q : l'en-tête forgé a été cru", got, "203.0.113.9")
	}
}

// TestXFFCruDepuisUnProxyDeclare : derrière un relais déclaré, on lit l'en-tête.
//
// Sans cela, toutes les requêtes portent l'adresse du relais : la limitation par
// source devient globale et le premier balayage venu freine tout le monde.
func TestXFFCruDepuisUnProxyDeclare(t *testing.T) {
	ProxiesDeConfiance = []string{"10.0.0.0/8"}
	t.Cleanup(func() { ProxiesDeConfiance = nil })

	got := SourceHTTP(requete("10.1.2.3:44000", "203.0.113.9"))
	if got != "203.0.113.9" {
		t.Errorf("source = %q, attendue %q", got, "203.0.113.9")
	}
}

// TestXFFDerniereValeurNonDeConfiance : on ne prend pas la première valeur.
//
// La chaîne se lit client, puis relais traversés. La partie gauche est écrite
// par le client : la lire donnerait exactement la falsification qu'on veut
// éviter, même derrière un relais légitime. On remonte donc depuis la droite
// jusqu'à la première valeur qui ne soit pas un relais connu.
func TestXFFDerniereValeurNonDeConfiance(t *testing.T) {
	ProxiesDeConfiance = []string{"10.0.0.1", "10.0.0.2"}
	t.Cleanup(func() { ProxiesDeConfiance = nil })

	got := SourceHTTP(requete("10.0.0.1:44000", "1.1.1.1, 203.0.113.9, 10.0.0.2"))
	if got != "203.0.113.9" {
		t.Errorf("source = %q, attendue %q", got, "203.0.113.9")
	}
}

// TestPortRetire : le port ne fait pas partie de la clé.
//
// Il change à chaque connexion : le garder donnerait une clé neuve par
// tentative, et le compteur par source ne dépasserait jamais un.
func TestPortRetire(t *testing.T) {
	ProxiesDeConfiance = nil

	for _, cas := range []struct{ entree, attendue string }{
		{"192.0.2.7:1234", "192.0.2.7"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"192.0.2.7", "192.0.2.7"},
	} {
		if got := SourceHTTP(requete(cas.entree, "")); got != cas.attendue {
			t.Errorf("SourceHTTP(%q) = %q, attendue %q", cas.entree, got, cas.attendue)
		}
	}
}

// TestIPv4MappeeNormalisee : ::ffff:10.0.0.1 et 10.0.0.1 sont la même machine.
//
// Sans normalisation, le même attaquant compterait deux fois moins en alternant
// les deux écritures.
func TestIPv4MappeeNormalisee(t *testing.T) {
	ProxiesDeConfiance = nil

	a := SourceHTTP(requete("[::ffff:10.0.0.1]:9000", ""))
	b := SourceHTTP(requete("10.0.0.1:9000", ""))
	if a != b {
		t.Errorf("%q et %q devraient désigner la même source", a, b)
	}
}

// TestRequeteNulle : pas de panique sur une requête absente.
func TestRequeteNulle(t *testing.T) {
	if got := SourceHTTP(nil); got != "" {
		t.Errorf("SourceHTTP(nil) = %q, attendue vide", got)
	}
}
