package action

import (
	"fmt"

	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	"vaultaire/core/permission"
)

// Réinitialisation du second facteur d'un tiers.
//
// # Pourquoi une clé à part
//
// `write:mfa` et non `write:update:user`, et la distinction tient aux deux sens
// à la fois.
//
// Débloquer un téléphone perdu est une tâche de support, fréquente et peu
// risquée : la confier ne doit pas emporter le droit de renommer ou de
// reconfigurer des comptes.
//
// Inversement, qui gère l'annuaire au quotidien ne devrait pas pouvoir retirer
// silencieusement le second facteur d'un administrateur — ce serait le moyen le
// plus discret de préparer une reprise de compte.
//
// # Pourquoi le secret est effacé, pas seulement désactivé
//
// Un secret conservé resterait une clé valide si le drapeau venait à être remis
// par un autre chemin. L'utilisateur ré-enrôle depuis son profil, ce qui est
// aussi ce qui garantit que c'est bien lui qui détient le nouveau téléphone.

// EnregistrerActionsMFA ajoute les actions de second facteur au registre.
func EnregistrerActionsMFA(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "user.reset_mfa",
		CleRBAC:  permission.ActionManageMFA,
		Portee:   porteeMFAUtilisateur,
		Resume:   "réinitialise le second facteur d'un compte",
		Executer: reinitialiserMFA,
	})
}

// porteeMFAUtilisateur exige le droit sur les domaines des GROUPES du compte.
//
// # Une nuance qui compte
//
// La version en ligne de commande passait par les groupes de la cible
// (GetGroupIDsFromUsername puis GetDomainListsFromGroupIDs), là où
// PorteeUtilisateur interroge directement les domaines du compte.
//
// Les deux devraient coïncider — un compte tient ses domaines de ses groupes —
// mais le chemin par les groupes REFUSE explicitement un compte sans groupe :
//
//	if len(targetGroupIDs) == 0 { return "Utilisateur introuvable ou sans groupe." }
//
// Cette différence est conservée, et volontairement. Un compte sans groupe n'a
// aucun domaine ; PorteeUtilisateur exigerait alors le droit global, ce qui est
// correct mais laisse un administrateur global agir sur un compte qui n'existe
// peut-être pas. Le refus explicite dit ce qui se passe.
func porteeMFAUtilisateur(p Params) ([]string, error) {
	cible := p.Get("username")
	if cible == "" {
		return nil, fmt.Errorf("utilisateur cible requis")
	}

	groupIDs, err := groupesDeLUtilisateur(cible)
	if err != nil {
		return nil, fmt.Errorf("groupes de %q illisibles : %w", cible, err)
	}
	if len(groupIDs) == 0 {
		return nil, fmt.Errorf("utilisateur %q introuvable ou sans groupe", cible)
	}

	domaines, err := domainesDesGroupes(groupIDs)
	if err != nil {
		return nil, fmt.Errorf("domaines de %q illisibles : %w", cible, err)
	}
	return domainesOuGlobal(domaines, nil)
}

func reinitialiserMFA(a Appelant, p Params) (Resultat, error) {
	cible := p.Get("username")
	if cible == "" {
		return Resultat{}, fmt.Errorf("utilisateur cible requis")
	}

	if err := dbauthpolicy.ResetMFA(database.GetDatabase(), cible, a.Username); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la réinitialisation du second facteur de %q : %w", cible, err)
	}

	return Resultat{
		Message: fmt.Sprintf(
			"Second facteur de %s réinitialisé. L'utilisateur devra le réenrôler à sa "+
				"prochaine connexion — jusque-là, son mot de passe suffit à se connecter.",
			cible),
		Donnees: map[string]string{"username": cible},
	}, nil
}
