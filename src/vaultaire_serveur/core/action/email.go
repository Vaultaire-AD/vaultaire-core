package action

import (
	"fmt"
	"net/mail"
	"strings"
)

// L'adresse e-mail d'un compte — TO-DO 271.
//
// Choisie à la création (`email`), changée ensuite par user.update. Sans
// choix, elle reste « compte@domaine », comme avant.

// EmailAuto est la valeur qui ramène une adresse choisie à l'automatique.
const EmailAuto = "auto"

// longueurMaxEmail : la colonne est un VARCHAR(255), et la RFC 5321 borne une
// adresse à 254 caractères.
const longueurMaxEmail = 254

// NormaliserEmail vérifie une adresse et la rend en minuscules.
//
// Une adresse NUE : « Alice <alice@x.fr> », accepté par net/mail, est refusé
// — le nom affiché n'a pas sa place dans l'attribut mail de l'annuaire.
//
// En minuscules : la colonne est UNIQUE, et « Alice@x.fr » à côté de
// « alice@x.fr » serait deux adresses pour la base et une seule pour une
// messagerie. La casse de la partie locale est théoriquement significative ;
// aucun serveur courant ne s'en sert.
func NormaliserEmail(brut string) (string, error) {
	s := strings.TrimSpace(brut)
	if s == "" {
		return "", fmt.Errorf("adresse e-mail vide")
	}
	if len(s) > longueurMaxEmail {
		return "", fmt.Errorf("adresse e-mail trop longue (%d caractères, %d au plus)", len(s), longueurMaxEmail)
	}
	if strings.ContainsAny(s, " \t\r\n<>\"") {
		return "", fmt.Errorf("adresse e-mail %q invalide : une adresse nue est attendue (nom@domaine)", s)
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s {
		return "", fmt.Errorf("adresse e-mail %q invalide (nom@domaine attendu)", s)
	}
	local, domaine, _ := strings.Cut(s, "@")
	if local == "" || domaine == "" || strings.Count(s, "@") != 1 {
		return "", fmt.Errorf("adresse e-mail %q invalide (nom@domaine attendu)", s)
	}
	if strings.HasPrefix(domaine, ".") || strings.HasSuffix(domaine, ".") || strings.Contains(domaine, "..") {
		return "", fmt.Errorf("adresse e-mail %q invalide : domaine mal formé", s)
	}
	return strings.ToLower(s), nil
}
