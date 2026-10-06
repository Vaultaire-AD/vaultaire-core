package webserveur

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"regexp"

	"vaultaire/core/auth/ratelimit"
	"vaultaire/core/logs"
)

// Jeton CSRF et en-têtes de sécurité du portail (TO-DO 103).
//
// # Le défaut
//
// La seule défense contre une requête forgée était `SameSite=Strict` sur le
// cookie de session. Il couvre la navigation inter-site ordinaire, pas un
// sous-domaine du même site enregistrable tenu par un tiers, ni un navigateur
// qui n'applique pas l'attribut. Or les actions d'administration sont des POST
// simples : créer un compte, lier une GPO, déclencher un kill switch. Et aucun
// en-tête de sécurité n'était posé : pas de Content-Security-Policy pour
// contenir une injection HTML future, rien contre l'inclusion dans un cadre.
//
// # Le jeton : celui de Nexus, sans état
//
// Nexus (vaultaire_nexus/internal/web/ui.go) exige sur chaque POST un champ
// « csrf » égal au jeton de la session. Même principe ici, avec une
// différence : le jeton n'est pas stocké, il est DÉRIVÉ du cookie de session
// par HMAC. Deux raisons :
//
//   - les sessions du portail vivent en base et plusieurs cores peuvent servir
//     le même navigateur. Un jeton tiré au hasard et gardé en mémoire par un
//     core serait inconnu du suivant ; un secret propre à chaque core aussi ;
//   - le dériver du cookie suffit : pour le calculer, il faut le cookie, qui
//     est HttpOnly. Qui le possède n'a plus besoin de forger une requête. Et
//     la dérivation est à sens unique : le jeton affiché dans la page ne
//     révèle pas le cookie.
//
// # Un seul endroit pour l'émettre, un seul pour le vérifier
//
// Le jeton est inséré dans CHAQUE formulaire POST au moment du rendu, par
// rendreDansTampon et rendreGabarit, que toutes les pages traversent. Les
// gabarits n'ont rien à écrire : un formulaire ajouté demain le reçoit sans
// qu'on y pense. L'écrire à la main dans les 83 formulaires aurait fait une
// liste à tenir — dont le 84ᵉ aurait été oublié.
//
// Il est vérifié par le middleware Proteger, devant toutes les routes, pour la
// même raison.
//
// # Ce qui n'est pas vérifié
//
// Un POST SANS cookie de session. Il n'agit au nom de personne : le
// gestionnaire le refusera faute de session, sauf la connexion elle-même et le
// second facteur, qui n'ont pas encore de session à protéger. Le dire ici
// plutôt que de le découvrir : la « CSRF de connexion » (connecter la victime
// au compte de l'attaquant) n'est pas couverte, et ne donne aucun droit sur le
// compte de la victime.

// champJetonCSRF est le nom du champ de formulaire, celui de Nexus.
const champJetonCSRF = "csrf"

// enteteJetonCSRF est l'en-tête accepté à la place du champ, pour un appel
// JavaScript qui n'envoie pas de formulaire. Celui de Nexus aussi.
const enteteJetonCSRF = "X-CSRF-Token"

// jetonCSRF dérive le jeton d'un cookie de session.
func jetonCSRF(cookie string) string {
	if cookie == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(cookie))
	mac.Write([]byte("vaultaire-portail-csrf-v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

// politiqueDeContenu est la Content-Security-Policy du portail.
//
//   - script-src 'self' : AUCUN script en ligne. C'est ce qui fait de la
//     politique une défense : une injection HTML qui glisserait un <script>
//     ou un attribut on* ne s'exécuterait pas. D'où le déplacement de tout le
//     JavaScript des gabarits vers /static ;
//   - style-src garde 'unsafe-inline' : des attributs style="…" restent dans
//     les gabarits. Un style injecté peut défigurer une page, pas agir ;
//   - fonts.googleapis.com et fonts.gstatic.com : les feuilles de style
//     importent leurs polices de Google Fonts. Les autoriser garde l'aspect du
//     portail ; les servir depuis /static fermerait cette dernière
//     dépendance externe — un portail sans accès à Internet retombe déjà sur
//     les polices du système ;
//   - img-src data: pour le QR code du second facteur ;
//   - frame-ancestors 'none' : le portail ne s'affiche dans aucun cadre, ce
//     qui ferme le détournement de clic sur un bouton de kill switch ;
//   - form-action 'self' : un formulaire injecté ne peut pas envoyer ailleurs
//     ce qu'on y tape.
const politiqueDeContenu = "default-src 'self'; script-src 'self'; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
	"font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; " +
	"object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// poserEntetesDeSecurite pose les en-têtes sur toutes les réponses.
func poserEntetesDeSecurite(h http.Header) {
	h.Set("Content-Security-Policy", politiqueDeContenu)
	// Redondant avec frame-ancestors pour les navigateurs qui ne lisent pas
	// la CSP.
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	// Les adresses du portail portent des noms de comptes et de groupes : elles
	// n'ont pas à partir vers un autre site.
	h.Set("Referrer-Policy", "same-origin")
	// Le portail n'est servi qu'en HTTPS. Un an, sans includeSubDomains : le
	// domaine parent peut porter des services qui ne sont pas en HTTPS, et ce
	// n'est pas au portail d'en décider pour eux.
	h.Set("Strict-Transport-Security", "max-age=31536000")
}

// reponseProtegee porte le jeton de la requête jusqu'au rendu.
//
// Les fonctions de rendu reçoivent la réponse, pas la requête : c'est par elle
// que le jeton leur arrive, sans changer la signature des dizaines d'appels.
type reponseProtegee struct {
	http.ResponseWriter
	jeton string
}

// Unwrap laisse http.ResponseController atteindre la réponse d'origine.
func (r *reponseProtegee) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// jetonDeLaReponse rend le jeton à insérer dans la page, vide s'il n'y en a pas.
func jetonDeLaReponse(w http.ResponseWriter) string {
	if r, ok := w.(*reponseProtegee); ok {
		return r.jeton
	}
	return ""
}

// renouvelerJeton suit un changement de cookie de session pendant la requête
// — un changement de mot de passe en pose un nouveau. Sans cela, la page rendue
// porterait le jeton de l'ANCIEN cookie, et son prochain envoi serait refusé.
func renouvelerJeton(w http.ResponseWriter, cookie string) {
	if r, ok := w.(*reponseProtegee); ok {
		r.jeton = jetonCSRF(cookie)
	}
}

// methodeSure dit si une méthode ne modifie rien, donc n'a pas besoin de jeton.
func methodeSure(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// Proteger pose les en-têtes de sécurité, et refuse toute requête modifiante
// portant un cookie de session sans le jeton qui lui correspond.
func Proteger(suivant http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		poserEntetesDeSecurite(w.Header())

		cookie := ""
		if c, err := r.Cookie("session_token"); err == nil {
			cookie = c.Value
		}
		attendu := jetonCSRF(cookie)

		if !methodeSure(r.Method) && attendu != "" {
			recu := r.Header.Get(enteteJetonCSRF)
			if recu == "" {
				// FormValue lit aussi un corps multipart : un envoi de fichier
				// porte le jeton comme les autres champs.
				recu = r.FormValue(champJetonCSRF)
			}
			if subtle.ConstantTimeCompare([]byte(recu), []byte(attendu)) != 1 {
				// SECURITY : c'est soit une page restée ouverte au-delà d'un
				// changement de session, soit une requête forgée. La source
				// distingue les deux à la relecture.
				logs.Write_Log("SECURITY", fmt.Sprintf(
					"web: %s %s refusé : jeton CSRF absent ou invalide (source %s)",
					r.Method, r.URL.Path, ratelimit.SourceHTTP(r)))
				http.Error(w, "Jeton de formulaire absent ou expiré : rechargez la page, puis recommencez.",
					http.StatusForbidden)
				return
			}
		}

		suivant.ServeHTTP(&reponseProtegee{ResponseWriter: w, jeton: attendu}, r)
	})
}

// balisePost reconnaît la balise ouvrante d'un formulaire POST.
//
// La méthode est cherchée DANS la balise, guillemets simples ou doubles, en
// majuscules ou non. Un formulaire sans méthode est un GET : il ne modifie
// rien et ne reçoit pas de jeton — le placer dans l'adresse le ferait fuiter
// dans l'historique et les journaux.
var (
	baliseForm  = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	methodePost = regexp.MustCompile(`(?i)\bmethod\s*=\s*["']?post\b`)
)

// injecterJetonCSRF ajoute le champ caché du jeton à chaque formulaire POST.
func injecterJetonCSRF(page []byte, jeton string) []byte {
	if jeton == "" {
		return page
	}
	champ := []byte(`<input type="hidden" name="` + champJetonCSRF + `" value="` +
		html.EscapeString(jeton) + `">`)
	return baliseForm.ReplaceAllFunc(page, func(balise []byte) []byte {
		if !methodePost.Match(balise) {
			return balise
		}
		out := make([]byte, 0, len(balise)+len(champ))
		out = append(out, balise...)
		return append(out, champ...)
	})
}
