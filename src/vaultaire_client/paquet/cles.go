package paquet

import (
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// NomFichierCles est le fichier déposé par « --join », à côté de
// gpo_signing_key.pem. Il peut porter DEUX clés pendant une rotation.
const NomFichierCles = "pkg_signing_key.pem"

// CheminCles rend l'emplacement du fichier de clés de confiance.
func CheminCles() string { return filepath.Join(storage.KeyPath, NomFichierCles) }

// ClesDeConfiance lit les clés de confiance de la machine.
//
// Relues à chaque appel, sans cache : une vérification de paquet est rare, et
// une clé ajoutée pour une rotation doit compter dès qu'elle est posée.
//
// L'ABSENCE du fichier est une erreur et non un « rien à vérifier » —
// contrairement à la clé des GPO, dont l'absence laisse passer les politiques
// pour la migration. Ici, sans clé, aucun paquet n'est installé : remplacer
// le binaire qui authentifie les sessions sur la foi d'un dépôt en lecture
// anonyme n'a pas de mode dégradé acceptable.
func ClesDeConfiance() ([]*rsa.PublicKey, error) {
	contenu, err := os.ReadFile(CheminCles())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s absent : cette machine n'accepte aucun paquet "+
				"(clé déposée par « vlt create -c … --join »)", CheminCles())
		}
		return nil, fmt.Errorf("lecture de %s : %w", CheminCles(), err)
	}
	return LireClesPubliques(contenu)
}
