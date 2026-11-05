package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// LES MARQUEURS PAR COMPTE — TO-DO 211.
//
// Un `user_git_config` posait la MÊME valeur à tous les comptes visés. Les
// champs listés dans champsAMarqueurs acceptent des marqueurs, remplacés ICI,
// au moment d'appliquer, pour le compte de la politique : la politique signée
// reste la même pour tout le groupe.
//
//	%u  nom du compte, sans domaine        alice
//	%U  compte complet                     alice@acme.lan
//	%d  domaine du compte                  acme.lan
//	%n  nom complet, tiré de l'annuaire    Alice Martin
//	%m  adresse de messagerie              alice.martin@acme.lan
//	%%  un % littéral
//
// %n et %m viennent du core, qui les livre avec la politique de compte
// (Policy.Identite) : le module NSS ne connaît que le nom de connexion. Le core
// refuse un marqueur inconnu à l'enregistrement de la GPO. L'agent, lui, le
// LAISSE tel quel, comme templated_file_deploy : une politique écrite avant le
// 211 peut porter un `%h` que git comprend (format de journal), et la faire
// échouer casserait ce qui marchait. Un %n ou %m SANS identité livrée, en
// revanche, fait échouer le module : poser un nom vide serait pire. La liste
// est figée par un test jumeau des deux côtés.
//
// # La dérive et la réapplication
//
// Le module est appliqué avec la valeur REMPLACÉE, et c'est elle que les
// vérificateurs comparent. Son empreinte prend un suffixe tiré de cette
// valeur : un compte renommé dans l'annuaire change son `%n`, donc l'empreinte,
// donc le module est rejoué.

// Identite est livrée par le core avec une politique de compte.
type Identite struct {
	NomComplet string `json:"nom_complet,omitempty"`
	Mail       string `json:"mail,omitempty"`
	Domaine    string `json:"domaine,omitempty"`
}

// champsAMarqueurs : les champs, par type de module, dont la valeur accepte
// les marqueurs. Pas user_cron (cron lit `%` comme un saut de ligne), pas
// user_ssh_client_config (`%u` y est déjà un marqueur de ssh), pas
// file_deploy (un contenu peut porter des `%` légitimes).
var champsAMarqueurs = map[string][]string{
	ModuleUserGitConfig: {"value"},
	ModuleUserEnv:       {"value"},
}

// remplacerMarqueurs remplace les marqueurs d'une valeur pour un compte.
func remplacerMarqueurs(v, compte string, id *Identite) (string, error) {
	if !strings.Contains(v, "%") {
		return v, nil
	}
	court, domaine, _ := strings.Cut(compte, "@")
	if domaine == "" && id != nil {
		domaine = id.Domaine
	}
	complet := compte
	if !strings.Contains(compte, "@") && domaine != "" {
		complet = compte + "@" + domaine
	}

	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '%' {
			b.WriteByte(v[i])
			continue
		}
		if i+1 >= len(v) {
			b.WriteByte('%') // « % » final : laissé tel quel
			continue
		}
		i++
		var rempl string
		switch v[i] {
		case 'u':
			rempl = court
		case 'U':
			rempl = complet
		case 'd':
			rempl = domaine
		case 'n':
			if id == nil || id.NomComplet == "" {
				return "", fmt.Errorf("%%n : nom complet du compte inconnu (le core ne l'a pas livre)")
			}
			rempl = id.NomComplet
		case 'm':
			if id == nil || id.Mail == "" {
				return "", fmt.Errorf("%%m : adresse du compte inconnue (le core ne l'a pas livree)")
			}
			rempl = id.Mail
		case '%':
			rempl = "%"
		default:
			// Inconnu : laissé tel quel (voir l'en-tête).
			b.WriteByte('%')
			b.WriteByte(v[i])
			continue
		}
		if (v[i] == 'u' || v[i] == 'U' || v[i] == 'd') && rempl == "" {
			return "", fmt.Errorf("%%%c : compte sans domaine connu", v[i])
		}
		b.WriteString(rempl)
	}
	return b.String(), nil
}

// developperMarqueurs remplace, dans une politique de COMPTE, les marqueurs
// des champs qui les acceptent. La politique est modifiée en place — c'est
// d'elle que BuildScopeState tire les empreintes enregistrées. Rend les
// erreurs par clé d'état : ces modules échoueront sans être appliqués.
func developperMarqueurs(p *Policy) map[string]string {
	if p == nil || p.Scope != ScopeUser {
		return nil
	}
	erreurs := map[string]string{}
	for i, m := range p.Modules {
		champs := champsAMarqueurs[m.Type]
		if len(champs) == 0 {
			continue
		}
		params := make(map[string]string, len(m.Params))
		for k, v := range m.Params {
			params[k] = v
		}
		change := false
		for _, c := range champs {
			brut, ok := params[c]
			if !ok || !strings.Contains(brut, "%") {
				continue
			}
			fait, err := remplacerMarqueurs(brut, p.Username, p.Identite)
			if err != nil {
				erreurs[m.StateKey] = "champ " + c + " : " + err.Error()
				break
			}
			params[c] = fait
			change = true
		}
		if !change {
			continue
		}
		m.Params = params
		m.Fingerprint = m.Fingerprint + "+" + empreinteDesChamps(params, champs)
		p.Modules[i] = m
	}
	return erreurs
}

func empreinteDesChamps(params map[string]string, champs []string) string {
	tries := append([]string(nil), champs...)
	sort.Strings(tries)
	h := sha256.New()
	for _, c := range tries {
		h.Write([]byte(c + "\x00" + params[c] + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
