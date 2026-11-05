package configuration_file

import (
	"fmt"
	"strings"

	"vaultaire/core/global/security/certimporte"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// poserChemin recopie une clé du fichier, ABSENTE comprise : retirer la ligne
// du fichier doit retirer l'import, comme pour les listes de SAN.
func poserChemin(cible *string, valeur *string) {
	if valeur == nil {
		*cible = ""
		return
	}
	*cible = strings.TrimSpace(*valeur)
}

// ConfigurerCertificatsImportes valide et charge les certificats fournis par
// fichier — TO-DO 262.
//
// Un défaut ARRÊTE le démarrage. Démarrer sur l'auto-signé à la place
// servirait aux clients un certificat qu'ils ne connaissent pas, et l'écart ne
// se verrait qu'à leurs poignées de main refusées.
func ConfigurerCertificatsImportes() error {
	certimporte.Journal = logs.Write_Log
	var erreurs []string
	for _, d := range []struct{ service, cert, cle, cles string }{
		{certimporte.ServiceLDAPS, storage.Ldaps_TLS_CertFile, storage.Ldaps_TLS_KeyFile, "ldap.ldaps_tls_cert_file / ldaps_tls_key_file"},
		{certimporte.ServiceWeb, storage.Web_TLS_CertFile, storage.Web_TLS_KeyFile, "website.web_tls_cert_file / web_tls_key_file"},
		{certimporte.ServiceAPI, storage.API_TLS_CertFile, storage.API_TLS_KeyFile, "api.api_tls_cert_file / api_tls_key_file"},
	} {
		if err := certimporte.Configurer(d.service, d.cert, d.cle); err != nil {
			erreurs = append(erreurs, fmt.Sprintf("certificat importé (%s) : %v", d.cles, err))
			continue
		}
		if s := certimporte.Pour(d.service); s != nil {
			logs.Write_Log("INFO", fmt.Sprintf("%s: certificat importé depuis %s", d.service, d.cert))
		}
	}
	if len(erreurs) > 0 {
		return fmt.Errorf("%s", strings.Join(erreurs, "\n  - "))
	}
	return nil
}
