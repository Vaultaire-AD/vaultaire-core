package action

import (
	"fmt"
	"strconv"

	dbcertificates "vaultaire/core/database/db_certificates"
	"vaultaire/core/logs"
)

// Actions sur les certificats TLS.
//
// # Pourquoi ces actions ne portent pas de clé RBAC
//
// Un certificat n'est pas une entité de l'annuaire : il ne porte pas de
// domaine. Aucune clé « catégorie:action:objet » ne le couvre — « certificate »
// ne figure pas dans RBACObjects — et aucune délégation par domaine ne peut
// s'y appliquer proprement.
//
// Or supprimer le certificat TLS de LDAPS ou de l'API interrompt le service
// pour tout le monde, sans rapport avec un périmètre délégué. L'appartenance au
// groupe protégé est le bon niveau : c'est déjà celui des restrictions GPO,
// pour la même raison — un réglage qui engage tout le parc n'appartient à aucun
// domaine en particulier.
//
// C'est ce cas qui a fait apparaître un défaut du registre lui-même. Sa
// première version exigeait une clé RBAC pour TOUTE action, ce qui confondait
// le principe avec son application : ce qui doit être impossible, c'est qu'une
// action n'ait aucun contrôle déclaré — pas qu'elle en utilise un autre que le
// RBAC. Voir le champ ExigeSuperadmin.

// EnregistrerActionsCertificat ajoute les actions certificat au registre.
func EnregistrerActionsCertificat(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom: "certificate.delete",
		// Pas de clé RBAC : voir l'explication en tête de fichier.
		ExigeSuperadmin: true,
		Portee:          PorteeGlobale,
		Resume:          "supprime un certificat TLS (réservé au groupe protégé)",
		Executer:        supprimerCertificat,
	})
}

// Accès à la base, isolés derrière des variables.
//
// Le test du message de suppression appelait supprimerCertificat directement et
// dépendait donc de ce que la couche base fait SANS base — un comportement que
// personne n'a choisi et qui peut changer sans qu'on le veuille. Ces deux points
// d'entrée le rendent explicite : le test dit ce que la base répond, et éprouve
// ce qui reste, c'est-à-dire la mise en forme et la trace.
var (
	lireCertificat      = dbcertificates.GetCertificateByID
	supprimerEnBaseCert = dbcertificates.DeleteCertificate
)

// supprimerCertificat retire un certificat de la base.
func supprimerCertificat(a Appelant, p Params) (Resultat, error) {
	brut := p.Get("certificate_id")
	if brut == "" {
		return Resultat{}, fmt.Errorf("identifiant de certificat requis")
	}

	id, err := strconv.Atoi(brut)
	if err != nil {
		return Resultat{}, fmt.Errorf("identifiant de certificat %q invalide : ce n'est pas un nombre", brut)
	}
	// Un identifiant négatif ou nul ne désigne aucune ligne. Le laisser passer
	// donnerait une suppression sans effet rapportée comme un succès.
	if id <= 0 {
		return Resultat{}, fmt.Errorf("identifiant de certificat %d invalide", id)
	}

	// Le certificat est LU avant d'être supprimé, pour son nom.
	//
	// « certificat 3 supprimé » n'apprend rien à qui relit le journal : il
	// faudrait retrouver à quoi correspondait l'identifiant 3 dans une table
	// d'où la ligne a précisément disparu. Le nom — ldaps, web, api — désigne le
	// service interrompu, qui est la seule chose qu'on cherche quand il tombe.
	//
	// La lecture sert une seconde fois : un identifiant inexistant devient une
	// vraie erreur au lieu d'une suppression sans effet rapportée comme un
	// succès. DeleteCertificate ne distingue pas « zéro ligne touchée » d'une
	// suppression réussie.
	cert, err := lireCertificat(id)
	if err != nil || cert == nil {
		return Resultat{}, fmt.Errorf("certificat %d introuvable", id)
	}
	nom := cert.Name

	if err := supprimerEnBaseCert(id); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression du certificat %q : %w", nom, err)
	}

	// Trace en SECURITY. Supprimer un certificat interrompt un service ; savoir
	// qui l'a fait, et LEQUEL, sont les deux premières questions posées quand
	// LDAPS cesse de répondre.
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"certificat %q (id %d) supprimé par %s", nom, id, a.Username))

	// Le message dit la conséquence. « Certificat supprimé » ne prépare pas
	// l'administrateur à voir un service tomber au redémarrage suivant.
	return Resultat{
		Message: fmt.Sprintf(
			"Certificat %q supprimé. Le service qui l'utilisait en régénérera un au "+
				"prochain démarrage — les clients qui avaient importé l'ancien devront "+
				"réimporter le nouveau.", nom),
		// La ligne d'audit nommera le certificat, pas son identifiant : les
		// paramètres reçus ne portent que « certificate_id ».
		Cible: "certificat " + nom,
	}, nil
}
