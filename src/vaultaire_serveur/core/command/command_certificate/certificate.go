// Package commandcertificate gère les certificats TLS du serveur.
//
//	vlt certificate list
//	vlt certificate show ldaps
//	vlt certificate regenerate ldaps [--dns nom1,nom2] [--ip 10.0.0.1,10.0.0.2]
//
// # Pourquoi une commande, et pas seulement une régénération automatique
//
// Remplacer un certificat change son empreinte. Tout client qui l'a importé dans
// son magasin de confiance — Keycloak, un connecteur applicatif, un annuaire
// secondaire — cesse alors de se connecter jusqu'à ce qu'on réimporte chez lui.
//
// Un serveur qui régénérerait de lui-même casserait donc silencieusement tous
// ses clients, au redémarrage, sans que personne ait rien demandé. C'est un
// geste d'administration : il doit être explicite.
package commandcertificate

import (
	"fmt"
	"strings"

	dbcertificates "vaultaire/core/database/db_certificates"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	duckykey "vaultaire/ducky-network/key_management"
)

// Certificate_Command traite `vlt certificate ...`.
//
// # Contrôle d'accès
//
// Régénérer le certificat qui identifie le serveur auprès de tout le parc est au
// moins aussi lourd que créer un client : même clé RBAC (`write:create:client`),
// exigée sur « * ». Un certificat n'appartient à aucun domaine.
//
// La lecture est séparée (`read:get:client`) : afficher le certificat PUBLIC est
// sans danger — c'est précisément ce qu'on distribue aux clients.
func Certificate_Command(commandList []string, senderGroupIDs []int, senderUsername string) string {
	if len(commandList) == 0 {
		return helpText()
	}
	sub := strings.ToLower(commandList[0])
	if sub == "-h" || sub == "--help" || sub == "help" {
		return helpText()
	}

	var actionKey string
	switch sub {
	case "regenerate":
		actionKey = "write:create:client"
	case "list", "show":
		actionKey = "read:get:client"
	default:
		return "Requête invalide. Essayez 'certificate -h'."
	}

	ok, reason := permission.CheckPermissionsMultipleDomains(senderGroupIDs, actionKey, []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"Permission refused: user=%s action=%s (certificate %s) reason=%s",
			senderUsername, actionKey, sub, reason))
		return "Permission refusée : " + reason
	}
	logs.Write_Log("INFO", fmt.Sprintf(
		"Permission used: user=%s action=%s (certificate %s)", senderUsername, actionKey, sub))

	switch sub {
	case "list":
		return listCertificates()
	case "show":
		return showCertificate(commandList[1:])
	default:
		return regenerate(commandList[1:], senderUsername)
	}
}

func listCertificates() string {
	certs, err := dbcertificates.GetAllCertificates()
	if err != nil {
		return "Lecture impossible : " + err.Error()
	}
	if len(certs) == 0 {
		return "Aucun certificat en base."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%-24s %-12s %s\n", "NOM", "TYPE", "COUVERTURE")
	for _, c := range certs {
		couverture := "-"
		if c.CertificateData != nil && *c.CertificateData != "" {
			couverture = ldaptools.CertSummary(*c.CertificateData)
		}
		fmt.Fprintf(&b, "%-24s %-12s %s\n", c.Name, c.CertificateType, couverture)
	}
	return b.String()
}

func showCertificate(args []string) string {
	nom := duckykey.LDAPSServerCertName
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		nom = nomCanonique(args[0])
	}

	certPEM, _, err := duckykey.GetCertificatePEMFromDB(nom)
	if err != nil {
		return fmt.Sprintf("Certificat %q introuvable : %v", nom, err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Certificat %s\n  %s\n\n", nom, ldaptools.CertSummary(certPEM))

	attendus := ldaptools.BuildSANSet(ldaptools.ConfiguredDNSNames(), ldaptools.ConfiguredIPs())
	issues := ldaptools.AuditServedCertificate(certPEM, attendus)
	if len(issues) == 0 {
		b.WriteString("Aucun défaut constaté.\n\n")
	} else {
		for _, i := range issues {
			marque := "avertissement"
			if i.Grave {
				marque = "PROBLÈME"
			}
			fmt.Fprintf(&b, "  [%s] %s\n", marque, i.Message)
		}
		b.WriteString("\n")
	}

	// La partie PUBLIQUE seulement. La clé privée n'a aucune raison de
	// traverser une session d'administration, et c'est le certificat que les
	// clients doivent importer.
	b.WriteString("À importer dans le magasin de confiance des clients :\n\n")
	b.WriteString(certPEM)
	return b.String()
}

func regenerate(args []string, senderUsername string) string {
	nom := duckykey.LDAPSServerCertName
	var dnsSupp, ipsSupp []string

	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "--dns", "--ip":
			if i+1 >= len(args) {
				return "Option " + args[i] + " : valeur manquante."
			}
			valeurs := strings.Split(args[i+1], ",")
			if strings.EqualFold(args[i], "--dns") {
				dnsSupp = append(dnsSupp, valeurs...)
			} else {
				ipsSupp = append(ipsSupp, valeurs...)
			}
			i++
		default:
			if !strings.HasPrefix(args[i], "-") {
				nom = nomCanonique(args[i])
			}
		}
	}

	if nom != duckykey.LDAPSServerCertName {
		return fmt.Sprintf("Seul le certificat %q est régénérable par cette commande pour le moment.",
			duckykey.LDAPSServerCertName)
	}

	sans := ldaptools.BuildSANSet(
		append(append([]string{}, ldaptools.ConfiguredDNSNames()...), dnsSupp...),
		append(append([]string{}, ldaptools.ConfiguredIPs()...), ipsSupp...))

	certPEM, keyPEM, err := ldaptools.GenerateLDAPSCertPEM(sans)
	if err != nil {
		return "Génération impossible : " + err.Error()
	}

	// Suppression puis création : SaveCertificateToDB refuse d'écraser, et
	// c'est un bon défaut ailleurs. Ici le remplacement est ce qu'on demande.
	if existant, errGet := dbcertificates.GetCertificateByName(nom); errGet == nil {
		if errDel := dbcertificates.DeleteCertificate(existant.ID); errDel != nil {
			return "Ancien certificat non supprimé : " + errDel.Error()
		}
	}
	if err := duckykey.SaveCertificateToDB(nom, "tls_cert", "Certificat TLS LDAPS", certPEM, keyPEM); err != nil {
		return "Enregistrement impossible : " + err.Error()
	}

	logs.Write_Log("INFO", fmt.Sprintf(
		"certificate: certificat LDAPS régénéré par %s — %s", senderUsername, ldaptools.CertSummary(certPEM)))

	var b strings.Builder
	fmt.Fprintf(&b, "Certificat LDAPS régénéré.\n  %s\n\n", ldaptools.CertSummary(certPEM))
	// Le redémarrage est obligatoire et facile à oublier : le certificat est
	// chargé une fois, à l'ouverture de l'écouteur TLS. Sans redémarrage, le
	// serveur continue de présenter l'ancien et le diagnostic repart à zéro.
	b.WriteString("⚠ Redémarrez le serveur : le certificat est chargé au démarrage de l'écouteur LDAPS.\n")
	b.WriteString("⚠ L'empreinte a changé — chaque client qui l'avait importé doit réimporter.\n\n")
	b.WriteString("À importer dans le magasin de confiance des clients :\n\n")
	b.WriteString(certPEM)
	return b.String()
}

// nomCanonique accepte les raccourcis d'usage.
func nomCanonique(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "ldaps", "ldap", "ldaps_server":
		return duckykey.LDAPSServerCertName
	default:
		return strings.TrimSpace(v)
	}
}

func helpText() string {
	return `Utilisation : vlt certificate <sous-commande>

  list                    certificats en base et ce qu'ils couvrent
  show [ldaps]            détail, défauts constatés, et PEM à distribuer
  regenerate ldaps        régénère le certificat LDAPS
      --dns nom1,nom2     noms DNS supplémentaires à couvrir
      --ip  10.0.0.1      adresses supplémentaires à couvrir

Les noms de la machine et ses adresses sont détectés automatiquement. Déclarez
en plus tout nom par lequel un client vous joint sans que le serveur le
connaisse : nom de service DNS, nom de conteneur, alias derrière un répartiteur.

Les clients Java — Keycloak et les connecteurs JNDI — ignorent le CommonName
depuis JDK 9 et exigent un nom alternatif (SAN) correspondant. Un certificat
sans SAN échoue avec « SSLHandshakeFailed », sans autre indice.

Le certificat étant auto-signé, il doit aussi être importé dans le magasin de
confiance de chaque client : « show » en affiche la partie publique.`
}
