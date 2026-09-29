package filter

import (
	"fmt"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// ErreurFiltre dit qu'un filtre porte quelque chose que le serveur ne sait pas
// évaluer.
//
// Un type d'erreur et non une simple chaîne, parce que l'appelant doit pouvoir
// en tirer le code de résultat LDAP à renvoyer.
type ErreurFiltre struct {
	Motif string
	// Code est le code de résultat LDAP qui correspond au refus.
	Code int
}

func (e *ErreurFiltre) Error() string { return e.Motif }

// Verifier parcourt un filtre AVANT toute évaluation et refuse ce que le serveur
// ne sait pas traiter.
//
// # Pourquoi une passe séparée
//
// Le switch d'évaluation se terminait par `default: return false`. Un filtre non
// géré ne faisait donc échouer aucune entrée : il les faisait TOUTES échouer, en
// silence, et le client recevait `success` avec zéro entrée.
//
// C'est le pire mode de panne : le client croit sa question posée et la réponse
// vraie. Un refus explicite est moins confortable et infiniment plus honnête —
// il dit au client que sa question n'a pas été comprise, ce qui est le cas.
//
// La vérification est faite UNE fois par recherche, et non par entrée : le motif
// ne dépend pas de l'entrée, et le journaliser par entrée noierait le journal
// sur une recherche qui porte sur des milliers de comptes.
//
// # L'invariant, dans un seul sens
//
// Tout type que Verifier ACCEPTE doit avoir un cas dans Evaluate. La réciproque
// est fausse et doit l'être : `FilterExtensible` est refusé ici et n'a aucun cas
// là-bas, c'est exactement le but.
//
// Un test impose ce sens-là, sans recopier la liste des cas — il vérifie qu'un
// filtre accepté retient bien une entrée faite pour le satisfaire. Sans lui, le
// `default` d'Evaluate redeviendrait le silence d'origine.
func Verifier(f *ldapstorage.LDAPFilter) error {
	if f == nil {
		return nil
	}

	switch f.Type {
	case ldapstorage.FilterAnd, ldapstorage.FilterOr:
		// Un AND ou un OR VIDE est refusé.
		//
		// La RFC 4511 §4.5.1 impose au moins un élément. Et l'évaluation en fait
		// quelque chose de dangereux : un AND vide est VRAI, donc retient toutes les
		// entrées — un filtre qui ne demande rien rendrait l'annuaire.
		//
		// Le parseur les refuse déjà. Ce contrôle est là parce que le filtre peut
		// venir d'ailleurs le jour où quelqu'un en construira un dans le code, et
		// parce qu'un refus explicite vaut mieux qu'une propriété qu'il faut aller
		// vérifier dans un autre paquet.
		if len(f.SubFilters) == 0 {
			return &ErreurFiltre{
				Motif: "filtre AND ou OR vide",
				Code:  ldapstorage.ResultProtocolError,
			}
		}
		for _, sous := range f.SubFilters {
			// Un sous-filtre ABSENT est refusé, et pas traité comme « pas de
			// filtre » : Evaluate rend VRAI pour un filtre nil, donc un nil glissé
			// dans un OR retiendrait l'annuaire entier.
			if sous == nil {
				return &ErreurFiltre{
					Motif: "sous-filtre absent",
					Code:  ldapstorage.ResultProtocolError,
				}
			}
			if err := Verifier(sous); err != nil {
				return err
			}
		}
		return nil

	case ldapstorage.FilterNot:
		// Un NOT porte exactement un sous-filtre (RFC 4511 §4.5.1). Zéro ou
		// plusieurs, c'est une trame malformée, et l'évaluation en faisait une
		// réponse vide et valide pour une question qui n'en était pas une.
		//
		// Le parseur refuse déjà cette forme : ce contrôle garde le paquet, pas la
		// trame. Il vaut pour tout filtre construit autrement qu'en décodant des
		// octets.
		if len(f.SubFilters) != 1 || f.SubFilters[0] == nil {
			return &ErreurFiltre{
				Motif: fmt.Sprintf("filtre NOT à %d sous-filtre(s), un seul est permis",
					len(f.SubFilters)),
				Code: ldapstorage.ResultProtocolError,
			}
		}
		return Verifier(f.SubFilters[0])

	case ldapstorage.FilterEquality, ldapstorage.FilterSubstring, ldapstorage.FilterPresent,
		ldapstorage.FilterGreaterOrEqual, ldapstorage.FilterLessOrEqual, ldapstorage.FilterApprox:
		return nil

	case ldapstorage.FilterExtensible:
		// REFUSÉ, alors qu'il était évalué comme une simple égalité.
		//
		// Un extensibleMatch porte une RÈGLE de correspondance, et éventuellement
		// le marqueur `dn:` ; les deux étaient ignorés. La chaîne AD
		// `(memberOf:1.2.840.113556.1.4.1941:=cn=…)` demande l'appartenance
		// TRANSITIVE à un groupe : y répondre par une égalité rend une liste de
		// membres FAUSSE, et une liste de membres fausse peut accorder ou refuser
		// un accès dans l'application qui la lit.
		//
		// Rendre un résultat faux est pire que de n'en rendre aucun. Le client
		// reçoit donc un refus qui nomme ce qui n'est pas géré.
		return &ErreurFiltre{
			Motif: fmt.Sprintf("extensible match non supporté sur %q", f.Attribute),
			Code:  ldapstorage.ResultInappropriateMatching,
		}

	default:
		// Le motif part au CLIENT : il ne porte donc pas le numéro interne du type.
		// La numérotation de LDAPFilterType n'est pas celle des étiquettes de la
		// RFC 4511 — l'interne 6 est `greaterOrEqual`, l'étiquette 6 est
		// `lessOrEqual` — et l'y mettre enverrait l'administrateur lire la mauvaise
		// ligne de la norme. Le journal du serveur, lui, le porte : voir le
		// `default` d'Evaluate.
		return &ErreurFiltre{
			Motif: "type de filtre non supporté",
			Code:  ldapstorage.ResultInappropriateMatching,
		}
	}
}
