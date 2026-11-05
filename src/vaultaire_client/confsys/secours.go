package confsys

import (
	"fmt"
	"strings"
)

// La porte de secours, vérifiée AVANT d'écrire une pile — TO-DO 117, point 4.
//
// Il n'existe pas de « pam -t ». Une pile fausse ne se découvre qu'en tentant
// de se connecter, c'est-à-dire trop tard, et sur une machine où l'on ne
// rentre plus. La seule porte qui reste alors est celle des comptes LOCAUX :
// pour eux, le module de Vaultaire rend PAM_IGNORE, la pile dit
// « ignore=ignore », et l'authentification continue vers celle de la
// distribution — root et la console de secours restent joignables.
//
// Le test-sentinelle (controle/sentinelle_secours_test.go) garde les gabarits
// du script. Ici, c'est le CANDIDAT que l'agent s'apprête à écrire, sur CETTE
// machine : une pile Debian personnalisée produit un candidat que personne n'a
// relu. Trois conditions :
//
//  1. la ligne d'authentification de Vaultaire existe ;
//  2. son contrôle contient « ignore=ignore » ;
//  3. plus bas, l'authentification de la distribution (system-auth,
//     password-auth, common-auth), sans ligne « die » ni « requisite » entre
//     les deux — elle couperait le chemin d'un compte local.

// modulesDAuthentification : ceux qui ouvrent les piles.
var modulesDAuthentification = []string{"pam_login_custom_module.so", "pam_ssh_auth_module.so"}

var pilesLocales = []string{"system-auth", "password-auth", "common-auth"}

// VerifierPorteDeSecours rend une erreur si la pile fermerait les comptes
// locaux.
func VerifierPorteDeSecours(pile string) error {
	ls := lignes(pile)
	debut := -1
	for i, l := range ls {
		champs := strings.Fields(l)
		if len(champs) < 2 || !estAuth(champs[0]) {
			continue
		}
		for _, m := range modulesDAuthentification {
			if strings.Contains(l, m) {
				debut = i
			}
		}
		if debut >= 0 {
			break
		}
	}
	if debut < 0 {
		return fmt.Errorf("porte de secours : aucune ligne « auth » ne charge le module de Vaultaire")
	}
	if !strings.Contains(controle(ls[debut]), "ignore=ignore") {
		return fmt.Errorf("porte de secours : le module n'est pas en « ignore=ignore » — un compte local serait refusé : %q",
			strings.TrimSpace(ls[debut]))
	}
	for _, l := range ls[debut+1:] {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		champs := strings.Fields(t)
		if champs[0] == "@include" && len(champs) > 1 && champs[1] == "common-auth" {
			return nil
		}
		if !estAuth(champs[0]) {
			continue
		}
		for _, p := range pilesLocales {
			if len(champs) >= 3 && (champs[1] == "substack" || champs[1] == "include") && champs[2] == p {
				return nil
			}
		}
		c := controle(t)
		if c == "requisite" || strings.Contains(c, "=die") {
			return fmt.Errorf("porte de secours : %q coupe le chemin d'un compte local avant la pile de la distribution", t)
		}
	}
	return fmt.Errorf("porte de secours : pas d'authentification locale (system-auth, password-auth, common-auth) après le module")
}

func estAuth(type_ string) bool { return type_ == "auth" || type_ == "-auth" }

// controle rend le contrôle d'une ligne PAM : « [ … ] » en entier, ou le mot.
func controle(l string) string {
	t := strings.TrimSpace(l)
	champs := strings.Fields(t)
	if len(champs) < 2 {
		return ""
	}
	if strings.HasPrefix(champs[1], "[") {
		i := strings.Index(t, "[")
		j := strings.Index(t, "]")
		if j > i {
			return t[i : j+1]
		}
	}
	return champs[1]
}
