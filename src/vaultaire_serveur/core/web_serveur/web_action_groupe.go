package webserveur

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"vaultaire/core/action"
)

// Exécution groupée : une action, plusieurs cibles, en une soumission.
//
// # Le problème que cela résout
//
// Ajouter douze comptes à un groupe demandait douze allers-retours : choisir
// dans la liste, cliquer, attendre le rechargement, recommencer. L'interface
// ne proposait rien d'autre parce que le pont ne savait traiter qu'une cible.
//
// # Le défaut qu'il ne fallait surtout pas introduire
//
// `parametresDepuisRequete` ne retient que la PREMIÈRE valeur d'un champ
// répété. Poser simplement `multiple` sur un <select> aurait donc produit le
// pire comportement possible : le formulaire envoie douze comptes, un seul est
// ajouté, la page affiche « utilisateur ajouté », et rien — ni message, ni
// journal — ne signale les onze autres. L'administrateur repart convaincu que
// son geste est fait.
//
// Tout ce fichier existe pour que cela ne puisse pas arriver.
//
// # Trois décisions, et leur raison
//
//  1. LE FORMULAIRE DÉCLARE. Un champ caché `bulk_field` nomme celui de ses
//     champs qui porte plusieurs cibles. Sans lui, le comportement est
//     exactement celui d'avant, à l'instruction près.
//
//     L'alternative — deviner, en cherchant quel champ arrive en plusieurs
//     exemplaires — a été écartée, et pas pour des raisons de style :
//     `r.Form` FUSIONNE le corps de la requête et la chaîne de requête de
//     l'URL. Les pages de détail postent vers `/admin/groups?group=X` ; le
//     jour où un formulaire porterait un champ nommé « group », la valeur de
//     l'URL s'ajouterait à celle du corps et la détection croirait à deux
//     cibles. Une heuristique qui se trompe ici agit sur la mauvaise entité.
//
//  2. LES VALEURS VIENNENT DE `r.PostForm`, JAMAIS DE `r.Form`. Corollaire du
//     point précédent : ce qui est exécuté ne peut venir que du corps de la
//     requête. Ajouter `?username=victime` à l'URL n'ajoute aucune cible.
//
//  3. UNE EXÉCUTION PAR CIBLE, DONC UN CONTRÔLE DE DROITS PAR CIBLE.
//     `action.Executer` résout les domaines de la cible et exige le droit
//     dessus. Grouper les cibles en un seul appel aurait fait porter le
//     contrôle sur la première, et les onze suivantes seraient passées avec
//     le droit d'une autre — une élévation de privilèges offerte par une
//     optimisation.
//
// # Ce qui n'est PAS garanti
//
// L'atomicité. Il n'y a pas de transaction : si la huitième cible échoue, les
// sept premières sont écrites. C'est assumé — chaque cible est une opération
// indépendante, et annuler sept rattachements réussis parce qu'un huitième
// compte a été supprimé entre-temps serait plus surprenant qu'utile. Le
// compte rendu dit exactement ce qui a été fait.

// executerAction est le point d'exécution, isolé en variable.
//
// Jamais réassigné en production : sa seule raison d'être est de permettre aux
// tests d'observer la BOUCLE — combien d'exécutions, avec quels paramètres
// chacune — sans base de données ni registre réel.
//
// C'est la garantie qui compte le plus dans ce fichier et la plus difficile à
// vérifier autrement : si les douze exécutions partaient avec les paramètres
// de la première, tout fonctionnerait, le compte rendu annoncerait douze
// réussites, et douze fois la même cible aurait été traitée.
var executerAction = action.Executer

// ChampCibles est le nom du champ caché par lequel un formulaire déclare
// qu'un de ses champs porte plusieurs cibles.
//
//	<input type="hidden" name="bulk_field" value="username">
//	<select name="username" multiple data-vlt-picker>…</select>
//
// Absent, rien ne change : une seule cible, comme avant.
const ChampCibles = "bulk_field"

// MaxCiblesGroupees plafonne le nombre de cibles d'une soumission.
//
// Chaque cible est une exécution complète — résolution des domaines, contrôle
// des droits, écriture. Une requête forgée portant cent mille valeurs
// immobiliserait une goroutine et la base pendant plusieurs minutes, sans
// qu'aucun contrôle ne s'y oppose : chacune des cent mille opérations est
// individuellement légitime.
//
// Au-delà du plafond, RIEN n'est exécuté. Refuser après avoir écrit deux cents
// lignes laisserait un état partiel qu'aucun message ne décrirait.
//
// 200 est très au-dessus de ce qu'une liste déroulante permet de désigner à la
// main, et très en dessous de ce qui pose problème.
const MaxCiblesGroupees = 200

// champsNonGroupables interdit de faire boucler le pont sur ses propres
// champs de transport.
//
// « action » désigne l'opération, pas sa cible : boucler dessus exécuterait
// plusieurs fois la même chose. « bulk_field » se désignerait lui-même. Ni
// l'un ni l'autre n'est une faille, mais les deux trahissent un formulaire mal
// écrit, et un refus explicite vaut mieux qu'un comportement absurde.
var champsNonGroupables = map[string]bool{
	"action":     true,
	ChampCibles:  true,
	"active_tab": true,
}

// ciblesDeclarees rend le nom du champ multi-valué déclaré par le formulaire.
//
// Chaîne vide si le formulaire n'en déclare pas : c'est le cas de tous les
// formulaires existants, et le chemin d'exécution reste alors le chemin
// d'origine.
func ciblesDeclarees(r *http.Request) string {
	return strings.TrimSpace(r.PostFormValue(ChampCibles))
}

// valeursDeCible extrait les cibles du CORPS de la requête.
//
// Nettoie, écarte les vides, et déduplique en conservant l'ordre d'envoi.
//
// La déduplication n'est pas cosmétique : deux fois la même cible, c'est une
// action réussie puis une action en échec — « alice est déjà membre » — donc
// un compte rendu qui annonce un échec là où l'administrateur n'a rien fait de
// mal.
func valeursDeCible(r *http.Request, champ string) []string {
	brutes, present := r.PostForm[champ]
	if !present {
		return nil
	}
	vues := make(map[string]bool, len(brutes))
	out := make([]string, 0, len(brutes))
	for _, v := range brutes {
		v = strings.TrimSpace(v)
		if v == "" || vues[v] {
			continue
		}
		vues[v] = true
		out = append(out, v)
	}
	return out
}

// parametresPourCible construit les paramètres d'UNE cible.
//
// L'écrasement du champ visé a lieu AVANT la résolution des alias, et l'ordre
// n'est pas indifférent. Si le champ groupé est une SOURCE d'alias —
// « target_user » → « username » —, écraser après laisserait le nom canonique
// figé sur la première valeur du lot : les douze exécutions viseraient alors
// le même compte, douze fois. Le compte rendu annoncerait douze réussites.
func parametresPourCible(r *http.Request, defauts action.Params, champ, valeur string) action.Params {
	p := action.Params{}
	for nom, valeurs := range r.Form {
		if len(valeurs) == 0 {
			continue
		}
		p[nom] = valeurs[0]
	}

	if champ != "" {
		p[champ] = valeur
	}

	// Le champ de transport n'est pas un paramètre métier. Les actions
	// ignorent ce qu'elles ne connaissent pas, mais le laisser passer
	// inviterait un jour une action à s'en servir.
	delete(p, ChampCibles)

	for source, canonique := range aliasParametres {
		if _, deja := p[canonique]; deja {
			continue
		}
		if v, present := p[source]; present {
			p[canonique] = v
		}
	}

	return parametresParDefaut(p, defauts)
}

// resultatDeCible retient ce qu'une cible a produit.
type resultatDeCible struct {
	cible string
	err   error
}

// executerParCible applique nomAction une fois par cible et agrège.
//
// Rend une erreur seulement si AUCUNE cible n'a abouti. Un succès partiel est
// un succès : les écritures ont eu lieu, la page doit se relire, et le message
// énumère les échecs. Transformer « 3 sur 4 » en erreur ferait croire que rien
// n'a été fait.
func executerParCible(r *http.Request, nomAction string, a action.Appelant,
	defauts action.Params, champ string) (action.Resultat, error) {

	if champsNonGroupables[champ] {
		return action.Resultat{}, fmt.Errorf(
			"le champ %q ne peut pas porter plusieurs cibles : c'est un champ de transport du formulaire", champ)
	}

	cibles := valeursDeCible(r, champ)
	if len(cibles) == 0 {
		// Un <select multiple> dont rien n'est coché n'envoie aucun champ. Le
		// formulaire arrive donc complet, avec son action, et sans cible. Sans
		// ce refus, l'action partirait avec une cible vide et rendrait un
		// message d'erreur métier qui n'expliquerait pas le vrai problème.
		return action.Resultat{}, errors.New("aucune cible sélectionnée")
	}
	if len(cibles) > MaxCiblesGroupees {
		return action.Resultat{}, fmt.Errorf(
			"%d cibles demandées, maximum %d par soumission : aucune n'a été traitée",
			len(cibles), MaxCiblesGroupees)
	}

	// Une seule cible : on rend le résultat et l'erreur de l'action tels
	// quels. Le message reste celui de l'action, et `errors.As` continue de
	// reconnaître *ErrRefusee — ce qu'une erreur agrégée ferait perdre, et
	// avec elle le mot « refusée » que MessageDActionPourAffichage ajoute.
	if len(cibles) == 1 {
		return executerAction(nomAction, a, parametresPourCible(r, defauts, champ, cibles[0]))
	}

	var reussies []string
	var echecs []resultatDeCible

	for _, cible := range cibles {
		_, err := executerAction(nomAction, a, parametresPourCible(r, defauts, champ, cible))
		if err != nil {
			echecs = append(echecs, resultatDeCible{cible: cible, err: err})
			continue
		}
		reussies = append(reussies, cible)
	}

	message := compteRenduGroupe(reussies, echecs)
	if len(reussies) == 0 {
		return action.Resultat{}, errors.New(message)
	}
	return action.Resultat{Message: message}, nil
}

// compteRenduGroupe rédige la phrase affichée après une exécution groupée.
//
// Elle doit permettre de savoir, sans recharger ni fouiller, ce qui a été fait
// et ce qui ne l'a pas été. Les cibles en échec sont donc TOUJOURS nommées,
// avec leur motif ; ce sont les réussites qu'on abrège quand elles sont
// nombreuses, parce que leur liste n'apprend rien de plus que leur nombre.
func compteRenduGroupe(reussies []string, echecs []resultatDeCible) string {
	const maxNommees = 8
	const maxMotifs = 5

	var b strings.Builder

	if n := len(reussies); n > 0 {
		fmt.Fprintf(&b, "%d réussite%s", n, pluriel(n))
		if n <= maxNommees {
			fmt.Fprintf(&b, " : %s", strings.Join(reussies, ", "))
		}
		b.WriteString(".")
	}

	if n := len(echecs); n > 0 {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "%d échec%s", n, pluriel(n))

		motifs := make([]string, 0, maxMotifs)
		for i, e := range echecs {
			if i >= maxMotifs {
				break
			}
			motifs = append(motifs, e.cible+" — "+MessageDActionPourAffichage(action.Resultat{}, e.err))
		}
		fmt.Fprintf(&b, " : %s", strings.Join(motifs, " ; "))
		if reste := len(echecs) - len(motifs); reste > 0 {
			fmt.Fprintf(&b, " ; et %d autre%s", reste, pluriel(reste))
		}
		b.WriteString(".")
	}

	return b.String()
}

func pluriel(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}
