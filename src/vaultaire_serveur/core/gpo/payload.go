package gpo

import (
	"fmt"
	"regexp"
	"strings"
)

// Validation des charges utiles de définitions.
//
// POINT D'EXTENSION — pour qu'un futur module ait un champ à contenu :
//  1. déclarer un PayloadKind dans restrictions.go ;
//  2. écrire son validateur et l'enregistrer dans payloadValidators ci-dessous ;
//  3. renseigner PayloadKind dans l'entrée dynamicFields du champ (defaults.go).
//
// Rien d'autre à toucher : la couche base stocke le contenu tel quel, l'interface
// web déduit du kind qu'il faut afficher un éditeur de contenu, et la validation
// des GPO passe automatiquement par le validateur enregistré.

// PayloadDescriptor décrit un kind pour l'interface d'administration.
type PayloadDescriptor struct {
	Kind PayloadKind
	// Label nomme le contenu attendu dans les formulaires.
	Label string
	// Placeholder est un exemple de contenu valide.
	Placeholder string
	// Help explique la syntaxe et ses limites.
	Help string
	// Multiline indique s'il faut une zone de texte plutôt qu'un champ simple.
	Multiline bool
}

// payloadDescriptors décrit chaque kind. PayloadNone n'y figure pas : un champ
// sans contenu n'a rien à afficher.
var payloadDescriptors = map[PayloadKind]PayloadDescriptor{
	PayloadCommandList: {
		Kind:        PayloadCommandList,
		Label:       "Commandes autorisées",
		Placeholder: "/usr/bin/systemctl restart mon-monitoring.service\n/usr/bin/journalctl -u mon-monitoring.service",
		Help: "Une commande par ligne, chemin absolu obligatoire, arguments fixes acceptés. " +
			"Le mot-clé ALL seul autorise toutes les commandes. " +
			"Les métacaractères shell et les jokers sont refusés : sans cela, une entrée comme " +
			"« /bin/sh » ou « /usr/bin/* » rendrait le jeu équivalent à un accès root complet.",
		Multiline: true,
	},
}

// PayloadDescriptorFor retourne le descripteur d'un kind.
func PayloadDescriptorFor(kind PayloadKind) (PayloadDescriptor, bool) {
	d, ok := payloadDescriptors[kind]
	return d, ok
}

// payloadValidators associe chaque kind à son validateur.
var payloadValidators = map[PayloadKind]func(string) error{
	PayloadCommandList: validateCommandListPayload,
}

// ValidatePayload valide une charge utile pour un kind donné.
func ValidatePayload(kind PayloadKind, payload string) error {
	if kind == PayloadNone {
		if strings.TrimSpace(payload) != "" {
			return fmt.Errorf("ce champ n'attend pas de contenu, seulement un nom")
		}
		return nil
	}
	validator, ok := payloadValidators[kind]
	if !ok {
		return fmt.Errorf("type de contenu inconnu : %q", kind)
	}
	if strings.TrimSpace(payload) == "" {
		return fmt.Errorf("contenu requis pour une définition de type %s", kind)
	}
	return validator(payload)
}

var (
	// commandPathRe : chemin absolu vers un exécutable.
	commandPathRe = regexp.MustCompile(`^/[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$`)
	// commandArgRe : argument fixe, sans expansion possible.
	commandArgRe = regexp.MustCompile(`^[A-Za-z0-9._:=@/,+-]+$`)
)

// commandForbiddenChars liste les caractères qui, dans une règle sudoers,
// permettent de sortir de la commande prévue : chaînage, redirection,
// substitution, ou joker élargissant la règle bien au-delà de l'intention.
const commandForbiddenChars = ";&|<>$`(){}[]*?!\\\"'\t"

// validateCommandListPayload valide une liste de commandes sudoers.
//
// La validation porte sur la FORME, pas sur l'intention : elle empêche
// l'injection de directives dans le fichier sudoers généré, mais n'empêche pas
// un administrateur d'autoriser délibérément une commande puissante. C'est le
// choix assumé du modèle « tout éditable » — le contenu est en revanche
// journalisé avec son auteur à chaque modification.
func validateCommandListPayload(payload string) error {
	var lines []string
	for _, l := range strings.Split(payload, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		lines = append(lines, t)
	}
	if len(lines) == 0 {
		return fmt.Errorf("aucune commande : le jeu serait vide")
	}

	for i, line := range lines {
		lineNo := i + 1

		if line == "ALL" {
			if len(lines) > 1 {
				return fmt.Errorf("ligne %d : ALL autorise déjà toutes les commandes, il ne peut pas être combiné avec d'autres lignes", lineNo)
			}
			return nil
		}
		if strings.ContainsAny(line, commandForbiddenChars) {
			return fmt.Errorf("ligne %d : caractère interdit (métacaractère shell ou joker) dans %q", lineNo, line)
		}

		parts := strings.Fields(line)
		if !commandPathRe.MatchString(parts[0]) {
			return fmt.Errorf("ligne %d : chemin absolu vers un exécutable attendu, reçu %q", lineNo, parts[0])
		}
		for _, arg := range parts[1:] {
			if !commandArgRe.MatchString(arg) {
				return fmt.Errorf("ligne %d : argument %q non conforme (lettres, chiffres, . _ : = @ / , + - uniquement)", lineNo, arg)
			}
		}
	}
	return nil
}

// PayloadKindFor retourne le type de contenu attendu par un champ, ou
// PayloadNone si le champ n'est qu'une liste de noms.
func PayloadKindFor(moduleType, fieldName string) PayloadKind {
	for _, f := range dynamicFields {
		if f.ModuleType == moduleType && f.FieldName == fieldName {
			return f.PayloadKind
		}
	}
	return PayloadNone
}

// FieldHasPayload indique si le champ porte des définitions à contenu.
func FieldHasPayload(moduleType, fieldName string) bool {
	return PayloadKindFor(moduleType, fieldName) != PayloadNone
}
