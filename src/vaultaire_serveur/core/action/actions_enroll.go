package action

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"vaultaire/core/clienttype"
	"vaultaire/core/database"
	dbenrollment "vaultaire/core/database/db_enrollment"
)

// Actions sur les clés d'enrôlement.
//
// # Pourquoi la portée est toujours globale
//
// Une clé d'enrôlement n'appartient à aucun domaine : le service qu'elle fera
// naître parlera au cluster entier. Exiger le droit sur « * » plutôt que sur un
// domaine est donc le bon niveau, et c'est ce que faisaient déjà les deux
// façades.
//
// # Une exigence qui dépend de ce qu'on demande
//
// Une clé visant un type qui porte l'assertion d'identité donne le pouvoir
// d'agir AU NOM DE N'IMPORTE QUEL UTILISATEUR. Ce n'est pas un droit qui se
// délègue par une clé RBAC ordinaire, et l'appartenance au groupe protégé est
// exigée en plus — mais seulement pour ces types-là.
//
// C'est le cas qui a fait apparaître ExigeSuperadminSi. Le champ précédent,
// ExigeSuperadmin, est un booléen fixé à l'écriture de l'action ; ici la
// réponse dépend du paramètre reçu.

// Bornes de saisie.
//
// Reprises des deux façades, qui les portaient déjà à l'identique. La base les
// revalide de toute façon — ces bornes servent à rendre un message clair avant
// d'aller jusque-là, pas à garantir quoi que ce soit.
const (
	enrolMaxUtilisations = 50
	enrolMaxMinutes      = 7 * 24 * 60
)

// EnregistrerActionsEnrolement ajoute les actions d'enrôlement au registre.
func EnregistrerActionsEnrolement(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "enroll.create_key",
		CleRBAC: "write:create:client",
		// Exigence SUPPLÉMENTAIRE quand le type demandé peut se faire passer
		// pour un utilisateur. Elle s'ajoute à la clé RBAC, elle ne la remplace
		// pas.
		ExigeSuperadminSi: cleDAssertionDIdentite,
		Portee:            PorteeGlobale,
		Resume:            "émet une clé d'enrôlement pour un service",
		Executer:          creerCleEnrolement,
	})

	r.MustEnregistrer(Definition{
		Nom:     "enroll.revoke_key",
		CleRBAC: "write:create:client",
		Portee:  PorteeGlobale,
		Resume:  "révoque une clé d'enrôlement",
		// Pas d'exigence supplémentaire à la révocation, même pour une clé
		// d'assertion d'identité : retirer un pouvoir n'est pas l'accorder.
		// Le rendre plus difficile que l'octroi retarderait la réaction le jour
		// où une clé fuite.
		Executer: revoquerCleEnrolement,
	})
}

// cleDAssertionDIdentite indique si le type demandé peut agir au nom d'un
// utilisateur.
//
// Rend false pour un type inconnu : la validation du type a lieu dans l'action,
// avec un message qui l'explique. Rendre true ici ferait refuser une faute de
// frappe avec « réservé au groupe protégé », ce qui enverrait l'administrateur
// chercher un problème de droits là où il n'y a qu'une coquille.
func cleDAssertionDIdentite(p Params) bool {
	t := strings.TrimSpace(p.Get("client_type"))
	if t == "" {
		return false
	}
	return clienttype.MayAssertUser(t)
}

// creerCleEnrolement émet une clé et la rend UNE SEULE FOIS.
func creerCleEnrolement(a Appelant, p Params) (Resultat, error) {
	typeClient := strings.TrimSpace(p.Get("client_type"))

	if err := clienttype.Validate(typeClient); err != nil {
		return Resultat{}, fmt.Errorf("type de client invalide : %w", err)
	}
	if !clienttype.IsService(typeClient) {
		return Resultat{}, fmt.Errorf(
			"%s est un agent : il se crée depuis la gestion des machines, il ne s'enrôle pas",
			typeClient)
	}

	utilisations, err := entierBorne(p.Get("uses"), "quota", 0, enrolMaxUtilisations)
	if err != nil {
		return Resultat{}, err
	}
	minutes, err := entierBorne(p.Get("expires_minutes"), "durée", 0, enrolMaxMinutes)
	if err != nil {
		return Resultat{}, err
	}

	secret, err := dbenrollment.GenerateSecret()
	if err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la génération du secret : %w", err)
	}

	// 0 vaut « illimité » sur les deux bornes. Une clé sans limite ne s'éteint
	// que par révocation : un geste explicite, jamais l'écoulement du temps.
	var expiration sql.NullTime
	if minutes > 0 {
		expiration = sql.NullTime{
			Time:  time.Now().Add(time.Duration(minutes) * time.Minute),
			Valid: true,
		}
	}

	if _, err := dbenrollment.CreateKey(database.GetDatabase(), secret,
		p.Get("label"), typeClient, utilisations, expiration, a.Username); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de l'émission de la clé : %w", err)
	}

	message := "Clé émise. Elle ne sera plus jamais affichée : copiez-la maintenant."
	if utilisations == 0 || !expiration.Valid {
		message += " Cette clé est sans limite : seule une révocation l'arrêtera."
	}

	return Resultat{
		Message: message,
		// Le secret voyage dans les données et NON dans le message : l'appelant
		// décide de son affichage. Le glisser dans une phrase le ferait
		// apparaître dans les journaux, où le message d'exécution est recopié —
		// et une clé d'enrôlement en clair dans un journal est une clé publiée.
		Donnees: map[string]string{
			"secret":      secret,
			"client_type": typeClient,
		},
	}, nil
}

func revoquerCleEnrolement(a Appelant, p Params) (Resultat, error) {
	brut := p.Get("key_id")
	if brut == "" {
		return Resultat{}, fmt.Errorf("identifiant de clé requis")
	}
	id, err := strconv.Atoi(brut)
	if err != nil {
		return Resultat{}, fmt.Errorf("identifiant de clé %q invalide : ce n'est pas un nombre", brut)
	}
	if id <= 0 {
		return Resultat{}, fmt.Errorf("identifiant de clé %d invalide", id)
	}

	if err := dbenrollment.RevokeKey(database.GetDatabase(), id, a.Username); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la révocation de la clé %d : %w", id, err)
	}

	return Resultat{Message: fmt.Sprintf(
		"Clé %d révoquée. Les services déjà enrôlés avec elle ne sont pas affectés : "+
			"ils ont leur propre paire de clés.", id)}, nil
}

// entierBorne analyse un entier et vérifie ses bornes, avec un message qui
// nomme le champ.
//
// Les deux façades rendaient « Le quota doit être un nombre entier » sans dire
// lequel des deux champs posait problème quand les deux étaient saisis.
func entierBorne(brut, libelle string, min, max int) (int, error) {
	if brut == "" {
		return 0, fmt.Errorf("%s requise : indiquez 0 pour aucune limite", libelle)
	}
	v, err := strconv.Atoi(brut)
	if err != nil {
		return 0, fmt.Errorf("%s invalide : %q n'est pas un nombre entier", libelle, brut)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("%s invalide : attendu entre %d (illimité) et %d, reçu %d",
			libelle, min, max, v)
	}
	return v, nil
}
