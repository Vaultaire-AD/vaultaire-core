// Package pagination tient, entre deux pages, ce qu'une recherche paginée n'a
// pas encore servi — RFC 2696, point 130.
//
// # Ce que le serveur promet
//
// Un client qui pagine doit recevoir chaque entrée UNE fois : ni doublon, ni
// trou, même si l'annuaire change pendant qu'il lit. C'est la seule difficulté
// réelle de la pagination ; l'encodage du contrôle est une formalité.
//
// # Comment la promesse est tenue
//
// Par un INSTANTANÉ. La première requête résout la recherche en entier, sert la
// première page, et range ici le reste. Les pages suivantes sortent de ce
// reste, sans réinterroger la base. Le jeu est donc figé à l'instant de la
// première requête : un compte créé pendant la lecture n'y figure pas, un
// compte supprimé y figure encore. C'est la sémantique d'une lecture cohérente,
// et c'est ce qu'un client attend.
//
// L'autre façon — recalculer la recherche à chaque page et reprendre « après la
// dernière entrée servie » — ne garde rien en mémoire, mais relit tout
// l'annuaire à chaque page : cent pages, cent lectures complètes. La recherche
// étant de toute façon résolue en mémoire avant le premier envoi, garder ce qui
// reste ne coûte que du temps de rétention.
//
// # Ce que ça coûte, et ce qui le borne
//
// De la mémoire, tenue entre deux pages. Quatre bornes, toutes dans
// ldapstorage : la taille d'une recherche, le total tenu par toutes, le nombre
// de curseurs par connexion, et une durée de vie. Un curseur meurt aussi avec
// sa connexion.
//
// # Le cookie
//
// Seize octets tirés au hasard, valables UNE fois : chaque page en rend un
// neuf. Un client qui rejoue une requête — réponse perdue, relance — avec un
// cookie déjà consommé reçoit un refus, pas la page SUIVANTE : avec un cookie
// fixe, la relance aurait sauté une page sans que personne le sache.
//
// Un cookie ne vaut que sur la connexion qui l'a reçu, pour le compte qui a
// ouvert la recherche, et pour la même recherche.
package pagination

import (
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// Les refus. Les trois premiers reçoivent la MÊME réponse côté client — un
// cookie qui ne vaut rien — ; ils sont distingués pour le journal.
var (
	// ErrCookieInconnu : jamais émis sur cette connexion, déjà consommé, ou
	// expiré.
	ErrCookieInconnu = errors.New("cookie de pagination inconnu, déjà consommé ou expiré")
	// ErrAutreCompte : la session a changé d'identité depuis l'ouverture.
	ErrAutreCompte = errors.New("cookie de pagination ouvert sous un autre compte")
	// ErrAutreRecherche : la requête n'est plus celle qui a ouvert le curseur.
	ErrAutreRecherche = errors.New("cookie de pagination employé pour une autre recherche")
	// ErrTropTenu : le plafond global d'entrées tenues est atteint.
	ErrTropTenu = errors.New("trop de recherches paginées en cours")
)

const tailleCookie = 16

type curseur struct {
	proprietaire string
	empreinte    string
	reste        []ldapinterface.LDAPEntry
	total        int
	tronque      bool
	expire       time.Time
	ouvert       time.Time
}

// Page est ce qu'une requête de pagination reçoit.
type Page struct {
	// Entrees : la page à servir.
	Entrees []ldapinterface.LDAPEntry
	// Cookie : à rendre au client. Vide quand la recherche est terminée.
	Cookie []byte
	// Total : nombre d'entrées de la recherche entière, connu dès la première
	// page puisque le jeu est figé.
	Total int
	// Tronque : la recherche a atteint une borne. À la DERNIÈRE page, le client
	// doit recevoir sizeLimitExceeded et non un succès — sans quoi il croirait
	// avoir tout lu.
	Tronque bool
}

var (
	mu       sync.Mutex
	curseurs = map[net.Conn]map[string]*curseur{}
	tenues   int

	// maintenant et nouveauCookie sont remplaçables par les tests.
	maintenant    = time.Now
	nouveauCookie = func() ([]byte, error) {
		c := make([]byte, tailleCookie)
		if _, err := rand.Read(c); err != nil {
			return nil, err
		}
		return c, nil
	}
)

func dureeDeVie() time.Duration {
	return time.Duration(ldapstorage.PagedCursorTTLSeconds) * time.Second
}

// retirer ôte un curseur et rend sa mémoire au compteur. mu doit être tenu.
func retirer(conn net.Conn, cle string) {
	parConn := curseurs[conn]
	c, ok := parConn[cle]
	if !ok {
		return
	}
	tenues -= len(c.reste)
	delete(parConn, cle)
	if len(parConn) == 0 {
		delete(curseurs, conn)
	}
}

// purger retire tous les curseurs expirés, toutes connexions confondues. mu
// doit être tenu.
//
// Appelée à chaque ouverture et à chaque reprise plutôt que par une tâche de
// fond : un curseur expiré ne gêne que par la mémoire qu'il retient, et c'est
// au moment où l'on en demande qu'il faut la rendre. Une connexion fermée rend
// la sienne tout de suite (OublierConnexion).
func purger() {
	t := maintenant()
	for conn, parConn := range curseurs {
		for cle, c := range parConn {
			if t.After(c.expire) {
				retirer(conn, cle)
			}
		}
	}
}

// Servir découpe un jeu de résultats FIGÉ : rend la première page, et range le
// reste s'il y en a un.
//
// entrees est le résultat complet de la recherche, déjà filtré par les droits
// et par le filtre. Il n'est pas copié : l'appelant ne doit plus y toucher.
//
// Rend ErrTropTenu SANS rien ranger si le reste ferait dépasser le plafond
// global. L'appelant doit alors refuser la recherche avant d'avoir envoyé une
// seule entrée — une première page sans suite possible serait un résultat
// tronqué présenté comme une page.
func Servir(conn net.Conn, proprietaire, empreinte string, entrees []ldapinterface.LDAPEntry, taille int, tronque bool) (Page, error) {
	if taille <= 0 || taille >= len(entrees) {
		// Tout tient dans une page : aucun état à garder.
		return Page{Entrees: entrees, Total: len(entrees), Tronque: tronque}, nil
	}

	reste := entrees[taille:]

	mu.Lock()
	defer mu.Unlock()
	purger()

	if ldapstorage.MaxPagedEntriesHeld > 0 && tenues+len(reste) > ldapstorage.MaxPagedEntriesHeld {
		return Page{}, ErrTropTenu
	}

	parConn := curseurs[conn]
	if parConn == nil {
		parConn = map[string]*curseur{}
		curseurs[conn] = parConn
	}
	// Une connexion qui ouvre recherche sur recherche sans jamais lire la suite
	// perd la plus ancienne. Un client réel en mène une, parfois deux.
	for ldapstorage.MaxPagedCursorsPerConnection > 0 && len(parConn) >= ldapstorage.MaxPagedCursorsPerConnection {
		plusAncien := ""
		for cle, c := range parConn {
			if plusAncien == "" || c.ouvert.Before(parConn[plusAncien].ouvert) {
				plusAncien = cle
			}
		}
		retirer(conn, plusAncien)
		parConn = curseurs[conn]
		if parConn == nil {
			parConn = map[string]*curseur{}
			curseurs[conn] = parConn
		}
	}

	cookie, err := nouveauCookie()
	if err != nil {
		return Page{}, err
	}
	t := maintenant()
	parConn[string(cookie)] = &curseur{
		proprietaire: proprietaire,
		empreinte:    empreinte,
		reste:        reste,
		total:        len(entrees),
		tronque:      tronque,
		expire:       t.Add(dureeDeVie()),
		ouvert:       t,
	}
	tenues += len(reste)

	return Page{Entrees: entrees[:taille], Cookie: cookie, Total: len(entrees), Tronque: tronque}, nil
}

// Reprendre rend la page suivante d'une recherche ouverte.
//
// Le cookie présenté est CONSOMMÉ, que la reprise aboutisse ou non : un cookie
// refusé pour une raison de fond — autre compte, autre recherche — ne doit pas
// pouvoir être rejoué jusqu'à trouver ce qui passe.
func Reprendre(conn net.Conn, cookie []byte, proprietaire, empreinte string, taille int) (Page, error) {
	mu.Lock()
	defer mu.Unlock()
	purger()

	cle := string(cookie)
	c, ok := curseurs[conn][cle]
	if !ok {
		return Page{}, ErrCookieInconnu
	}
	if c.proprietaire != proprietaire {
		retirer(conn, cle)
		return Page{}, ErrAutreCompte
	}
	if c.empreinte != empreinte {
		retirer(conn, cle)
		return Page{}, ErrAutreRecherche
	}

	if taille <= 0 || taille >= len(c.reste) {
		// Dernière page.
		page := Page{Entrees: c.reste, Total: c.total, Tronque: c.tronque}
		retirer(conn, cle)
		return page, nil
	}

	suivant, err := nouveauCookie()
	if err != nil {
		retirer(conn, cle)
		return Page{}, err
	}
	page := Page{Entrees: c.reste[:taille], Cookie: suivant, Total: c.total, Tronque: c.tronque}

	// Le curseur change de cookie : l'ancien ne vaut plus rien.
	c.reste = c.reste[taille:]
	c.expire = maintenant().Add(dureeDeVie())
	tenues -= taille
	delete(curseurs[conn], cle)
	curseurs[conn][string(suivant)] = c
	return page, nil
}

// Abandonner ferme une recherche avant sa fin — ce qu'un client demande par
// une taille de page à zéro avec son cookie (RFC 2696 §3). Un cookie inconnu
// n'est pas une erreur : il n'y a simplement rien à fermer.
func Abandonner(conn net.Conn, cookie []byte) {
	mu.Lock()
	defer mu.Unlock()
	retirer(conn, string(cookie))
}

// OublierConnexion rend la mémoire de tous les curseurs d'une connexion. À
// appeler à sa fermeture.
func OublierConnexion(conn net.Conn) {
	mu.Lock()
	defer mu.Unlock()
	for cle := range curseurs[conn] {
		retirer(conn, cle)
	}
}

// Etat rend le nombre de curseurs ouverts et d'entrées tenues. Pour les tests
// et le diagnostic.
func Etat() (ouverts, entreesTenues int) {
	mu.Lock()
	defer mu.Unlock()
	for _, parConn := range curseurs {
		ouverts += len(parConn)
	}
	return ouverts, tenues
}
