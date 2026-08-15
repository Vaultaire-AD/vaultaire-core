package dbgpo

import (
	"database/sql"
	"fmt"

	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// SetPolicyDriftMode change le mode de dérive d'une GPO.
//
// # Pourquoi ce n'est pas un paramètre de UpdatePolicyMeta
//
// UpdatePolicyMeta écrit la description ET l'activation d'un coup, parce qu'il
// sert un formulaire qui envoie les deux. Y ajouter le mode obligerait tout
// appelant qui ne veut changer que le mode — la ligne de commande — à relire la
// GPO et à repasser les deux autres champs. Le jour où l'un d'eux serait oublié,
// une commande de réglage du mode effacerait une description ou désactiverait
// une GPO en silence.
//
// # La version est incrémentée
//
// C'est ce qui fait que le changement atteint le parc. La version entre dans la
// forme canonique (voir gpo.CanonicalJSON), donc dans l'empreinte de politique :
// sans incrément, un agent dont la politique est par ailleurs identique
// continuerait de recevoir « rien à faire », et le nouveau mode ne s'appliquerait
// qu'à la prochaine modification de contenu.
//
// Le mode entre lui-même dans l'empreinte, ce qui suffirait. L'incrément reste
// là parce qu'il est la convention de ce fichier — toute écriture sur une GPO
// fait avancer sa version — et parce qu'une version qui ne bouge pas quand la
// GPO change rendrait la colonne inutilisable pour dire « qu'est-ce qui a
// bougé depuis ? ».
func SetPolicyDriftMode(db *sql.DB, id int, mode gpo.DriftMode) error {
	if db == nil {
		return fmt.Errorf("gpo: connexion base nulle")
	}
	if !gpo.IsValidDriftMode(string(mode)) {
		return fmt.Errorf("mode de dérive %q invalide (attendu : %s ou %s)",
			mode, gpo.DriftEnforce, gpo.DriftAudit)
	}

	res, err := db.Exec(
		`UPDATE gpo SET drift_mode = ?, version = version + 1 WHERE id_gpo = ?`,
		string(mode), id,
	)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBGeneric,
			"gpo: mise à jour du mode de dérive échouée : "+err.Error())
		return fmt.Errorf("mise à jour du mode de dérive impossible : %v", err)
	}

	// Zéro ligne touchée n'est pas une réussite silencieuse : l'identifiant ne
	// correspond à aucune GPO, et rendre nil ferait afficher « mode changé » à
	// l'appelant pour un changement qui n'a pas eu lieu.
	//
	// MariaDB rend 0 quand la valeur écrite est identique à l'ancienne. On ne
	// peut donc pas distinguer les deux cas ici — mais la version est
	// incrémentée dans la même requête, donc une ligne existante est TOUJOURS
	// modifiée. Zéro signifie bien « aucune ligne de ce nom ».
	touched, err := res.RowsAffected()
	if err == nil && touched == 0 {
		return fmt.Errorf("aucune GPO d'identifiant %d", id)
	}

	return nil
}
