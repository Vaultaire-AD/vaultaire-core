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

// SansCle : le numéro déclaré par une machine qui n'a PAS de fichier de clés
// (TO-DO 233). Elle refuse tout paquet ; avec 0, le core la comptait parmi
// celles qui tiennent le jeu de l'installation.
const SansCle = -1

// NumeroDuJeu rend le numéro du jeu de clés que la machine tient — 0 pour le
// fichier de l'installation (TO-DO 207), SansCle sans fichier.
func NumeroDuJeu() int {
	contenu, err := os.ReadFile(CheminCles())
	if err != nil {
		if os.IsNotExist(err) {
			return SansCle
		}
		return 0
	}
	return NumeroDuFichier(string(contenu))
}

// AppliquerJeu vérifie un jeu reçu du core et, s'il est plus haut que celui
// de la machine et signé par une clé qu'elle tient DÉJÀ, remplace son fichier.
// Rend le jeu appliqué ; une erreur sinon — rien n'a changé.
//
// Écriture atomique (fichier temporaire, rename) : un fichier à moitié écrit
// ferait refuser tous les paquets, et c'est le seul fichier qui en juge.
func AppliquerJeu(corps string, env Enveloppe) (Jeu, error) {
	cles, err := ClesDeConfiance()
	if err != nil {
		return Jeu{}, err
	}
	j, err := VerifierJeu(corps, env, cles)
	if err != nil {
		return Jeu{}, err
	}
	if courant := NumeroDuJeu(); j.Numero <= courant {
		return Jeu{}, fmt.Errorf("jeu n°%d refusé : la machine tient déjà le n°%d (rejeu ?)", j.Numero, courant)
	}
	texte, err := FichierCles(j)
	if err != nil {
		return Jeu{}, err
	}
	tmp := CheminCles() + ".vaultaire-jeu"
	if err := os.WriteFile(tmp, []byte(texte), 0o644); err != nil {
		return Jeu{}, fmt.Errorf("écriture du jeu : %w", err)
	}
	if err := os.Rename(tmp, CheminCles()); err != nil {
		_ = os.Remove(tmp)
		return Jeu{}, fmt.Errorf("pose du jeu : %w", err)
	}
	return j, nil
}
