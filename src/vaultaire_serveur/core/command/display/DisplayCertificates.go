package display

import (
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	"vaultaire/core/storage"
)

// DisplayCertificates affiche les certificats du serveur.
//
// La mise en forme vivait dans commandcertificate, où l'interface web ne
// pouvait pas l'atteindre. Elle est ici pour que les deux façades montrent la
// même chose du même jeu de données.
func DisplayCertificates(certs []storage.Certificate) string {
	if len(certs) == 0 {
		return "Aucun certificat en base.\n"
	}

	tb := NouvelleTable("NOM", "TYPE", "COUVERTURE")
	for _, c := range certs {
		// La couverture — les noms et adresses que le certificat déclare —
		// n'est calculée que si les données sont présentes. Un certificat sans
		// PEM rend « — » plutôt qu'une chaîne vide : la case blanche se
		// confondrait avec un défaut d'affichage.
		couverture := ""
		if c.CertificateData != nil && *c.CertificateData != "" {
			couverture = ldaptools.CertSummary(*c.CertificateData)
		}
		tb.Ajouter(Valeur(c.Name), Valeur(c.CertificateType), Valeur(couverture))
	}
	return "Certificats du serveur\n\n" + tb.String()
}
