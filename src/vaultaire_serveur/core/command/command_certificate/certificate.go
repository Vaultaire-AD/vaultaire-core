// Package commandcertificate gère les certificats TLS du serveur.
//
//	vlt certificate list
//	vlt certificate show ldaps
//	vlt certificate regenerate ldaps|web|api|all [--dns nom1,nom2] [--ip 10.0.0.1,10.0.0.2]
//
// # Pourquoi le portail et l'API sont régénérables
//
// Leurs certificats sont produits une seule fois, au premier démarrage, puis
// conservés en base. Une déclaration `web_tls_dns_names` ajoutée ensuite en
// configuration restait donc sans effet, et rien ne le signalait : le
// navigateur affichait ERR_CERT_COMMON_NAME_INVALID et le seul recours était de
// supprimer la ligne en base à la main.
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

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	dbcertificates "vaultaire/core/database/db_certificates"
	"vaultaire/core/global/security"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
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

	appelant := action.Appelant{Username: senderUsername, GroupIDs: senderGroupIDs}

	switch sub {
	case "list":
		res, err := action.Executer("certificate.list", appelant, action.Params{})
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		certs, _ := res.Donnees.([]storage.Certificate)
		return display.DisplayCertificates(certs)

	case "show", "fingerprint":
		// L'empreinte du core et la fiche d'un certificat sont deux lectures
		// du même objet : même droit, read:certificate.
		if sub == "fingerprint" {
			if refus := verifierLectureCertificat(appelant); refus != "" {
				return refus
			}
			return afficherEmpreinteCore()
		}
		return showCertificate(commandList[1:], appelant)

	case "regenerate":
		// Régénérer exige write:certificate et non plus write:create:client.
		//
		// Le changement d'empreinte casse tous les clients qui l'ont importée
		// dans leur magasin de confiance : ce n'est pas la même décision que
		// créer une machine, et le droit ne doit plus être le même.
		res, err := action.Executer("certificate.regenerate", appelant,
			action.Params{"args": strings.Join(commandList[1:], " ")})
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		return res.Message

	default:
		return "Requête invalide. Essayez « certificate -h »."
	}
}

// verifierLectureCertificat contrôle `fingerprint` sans rien exécuter.
//
// L'empreinte du core se calcule à partir de la clé en mémoire : ce n'est pas
// une lecture de la table des certificats, donc pas une action. Mais c'est une
// lecture de la même nature, et elle doit exiger le même droit.
//
// Controler plutôt qu'une vérification recopiée : c'est le MÊME chemin de
// décision que les actions, avec la même clé, la même portée et le même
// journal. Rien n'est exécuté — voir Executeur.Controler.
func verifierLectureCertificat(a action.Appelant) string {
	if _, err := action.Defaut.Controler("certificate.list", a, action.Params{}); err != nil {
		return commandaction.MessageDErreur(err)
	}
	return ""
}

// BrancherRegeneration raccorde la régénération au registre.
//
// Appelée au démarrage. L'inversion évite un cycle : l'action ne peut pas
// importer ce paquet, qui l'importe déjà.
func BrancherRegeneration() {
	action.RegenererCertificat = func(a action.Appelant, p action.Params) (string, error) {
		args := strings.Fields(p.Get("args"))
		return regenerate(args, a.Username), nil
	}
}

// afficherEmpreinteCore répond à `vlt certificate fingerprint`.
//
// # À quoi cela sert
//
// Quand un agent refuse de démarrer parce que la clé du core ne correspond plus
// à l'empreinte qu'il connaît, deux explications se présentent : le core a
// changé de clé, ou quelqu'un répond à sa place. Ces deux cas appellent des
// réponses opposées — accepter la nouvelle clé, ou surtout pas.
//
// Les distinguer suppose de connaître l'empreinte réelle du core, obtenue
// depuis le core lui-même. C'est ce que rend cette commande.
//
// Sans elle, l'administrateur n'a d'autre issue que d'effacer le fichier et
// d'espérer — c'est-à-dire d'accepter d'avance ce que la vérification était
// censée détecter.
func afficherEmpreinteCore() string {
	empreinte, err := duckykey.EmpreinteDuCore()
	if err != nil {
		return "Empreinte indisponible : " + err.Error()
	}

	var b strings.Builder
	b.WriteString("Empreinte de la clé publique du core\n\n")
	b.WriteString("  " + empreinte + "\n\n")
	b.WriteString("C'est la valeur que les agents attendent dans\n")
	b.WriteString("  /etc/vaultaire_client/.ssh/" + duckykey.CoreFingerprintFileName + "\n\n")
	b.WriteString("Elle y est déposée par « vlt create -join », sur le canal SSH.\n\n")
	b.WriteString("Si un agent refuse de démarrer en signalant une empreinte différente :\n")
	b.WriteString("  - l'empreinte qu'il a reçue correspond à celle ci-dessus → le core a\n")
	b.WriteString("    changé de clé ; effacez le fichier ci-dessus sur cet agent ainsi que\n")
	b.WriteString("    serveurpublickey.pem, puis redémarrez-le ;\n")
	b.WriteString("  - elle ne correspond pas → quelque chose répond à la place du core.\n")
	b.WriteString("    N'effacez rien : cela reviendrait à accepter l'imposteur.\n")
	return b.String()
}

// listCertificates a été retirée : l'action certificate.list lit la table et
// display.DisplayCertificates la met en forme, pour les deux façades.

func showCertificate(args []string, appelant action.Appelant) string {
	if refus := verifierLectureCertificat(appelant); refus != "" {
		return refus
	}
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

	issues := ldaptools.AuditServedCertificate(certPEM, nomsAttendus(nom))
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

// nomsAttendus rend les noms que le certificat DEVRAIT couvrir.
//
// Le jeu dépend du service : LDAPS est configuré par `ldaps_tls_dns_names`, le
// portail et l'API par `web_tls_dns_names`. Ce sont deux entrées distinctes de
// la configuration, parce que ces services ne sont pas joints par les mêmes
// noms — le portail par une URL en signet, l'annuaire par un alias de service.
//
// Avant, `show web` était audité contre les noms du LDAPS : un certificat
// parfaitement valide se voyait reprocher de ne pas couvrir un alias d'annuaire
// qui n'avait rien à y faire, et un vrai défaut se serait perdu dans ce bruit.
func nomsAttendus(nom string) ldaptools.SANSet {
	if nom == duckykey.LDAPSServerCertName {
		return ldaptools.BuildSANSet(ldaptools.ConfiguredDNSNames(), ldaptools.ConfiguredIPs())
	}
	return ldaptools.BuildSANSet(storage.Web_TLS_DNSNames, storage.Web_TLS_IPs)
}

// certificatsRegenerables décrit ce que la commande sait reconstruire.
//
// # Pourquoi le portail et l'API ont rejoint la liste
//
// Ils en étaient absents, et la commande refusait explicitement tout autre nom
// que LDAPS. Or leurs certificats sont produits UNE FOIS, au premier démarrage,
// puis conservés en base : `web_tls_dns_names` ajouté ensuite dans la
// configuration n'avait aucun effet, et rien ne le signalait.
//
// L'administrateur se retrouvait devant un avertissement de navigateur
// (ERR_CERT_COMMON_NAME_INVALID) sans autre recours que de supprimer la ligne
// en base à la main. Le correctif de l'identité des certificats était donc
// écrit, testé — et inatteignable sur toute installation déjà démarrée.
var certificatsRegenerables = map[string]struct {
	nom         string
	description string
	service     string
}{
	duckykey.LDAPSServerCertName: {duckykey.LDAPSServerCertName, "Certificat TLS LDAPS", "l'écouteur LDAPS"},
	duckykey.WebServerCertName:   {duckykey.WebServerCertName, "Certificat TLS portail web", "le portail web"},
	duckykey.APIServerCertName:   {duckykey.APIServerCertName, "Certificat TLS API REST", "l'API REST"},
}

func regenerate(args []string, senderUsername string) string {
	nom := duckykey.LDAPSServerCertName
	var dnsSupp, ipsSupp []string
	tous := false

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
				if c := nomCanonique(args[i]); c == "all" {
					tous = true
				} else {
					nom = c
				}
			}
		}
	}

	if tous {
		var b strings.Builder
		// Ordre fixe : une sortie qui change d'ordre d'une exécution à l'autre
		// est pénible à comparer, et les maps Go n'en garantissent aucun.
		for _, n := range []string{duckykey.LDAPSServerCertName, duckykey.WebServerCertName, duckykey.APIServerCertName} {
			b.WriteString(regenererUn(n, dnsSupp, ipsSupp, senderUsername))
			b.WriteString("\n")
		}
		return b.String()
	}

	if _, connu := certificatsRegenerables[nom]; !connu {
		return fmt.Sprintf("Certificat %q inconnu. Valeurs acceptées : ldaps, web, api, all.", nom)
	}
	return regenererUn(nom, dnsSupp, ipsSupp, senderUsername)
}

// regenererUn reconstruit un certificat et le remplace en base.
func regenererUn(nom string, dnsSupp, ipsSupp []string, senderUsername string) string {
	info := certificatsRegenerables[nom]

	var certPEM, keyPEM string
	var err error

	if nom == duckykey.LDAPSServerCertName {
		// LDAPS garde son propre générateur : ses SAN sont construits par
		// BuildSANSet, qui applique les règles particulières attendues par les
		// clients Java — voir docs/exploitation/ldaps_keycloak.md.
		sans := ldaptools.BuildSANSet(
			append(append([]string{}, ldaptools.ConfiguredDNSNames()...), dnsSupp...),
			append(append([]string{}, ldaptools.ConfiguredIPs()...), ipsSupp...))
		certPEM, keyPEM, err = ldaptools.GenerateLDAPSCertPEM(sans)
	} else {
		// Portail et API : même générateur qu'au premier démarrage, donc mêmes
		// CommonName et SubjectAltName. Régénérer ne doit pas produire un
		// certificat d'une autre nature que celui qu'on remplace.
		certPEM, keyPEM, err = security.GenerateSelfSignedCertPEMAvec(dnsSupp, ipsSupp)
	}
	if err != nil {
		return fmt.Sprintf("Certificat %s : génération impossible — %v\n", nom, err)
	}

	// Suppression puis création : SaveCertificateToDB refuse d'écraser, et
	// c'est un bon défaut ailleurs. Ici le remplacement est ce qu'on demande.
	if existant, errGet := dbcertificates.GetCertificateByName(nom); errGet == nil {
		if errDel := dbcertificates.DeleteCertificate(existant.ID); errDel != nil {
			return fmt.Sprintf("Certificat %s : ancien non supprimé — %v\n", nom, errDel)
		}
	}
	if err := duckykey.SaveCertificateToDB(nom, "tls_cert", info.description, certPEM, keyPEM); err != nil {
		return fmt.Sprintf("Certificat %s : enregistrement impossible — %v\n", nom, err)
	}

	logs.Write_Log("INFO", fmt.Sprintf(
		"certificate: certificat %s régénéré par %s — %s", nom, senderUsername, ldaptools.CertSummary(certPEM)))

	var b strings.Builder
	fmt.Fprintf(&b, "Certificat %s régénéré.\n  %s\n\n", nom, ldaptools.CertSummary(certPEM))
	// Le redémarrage est obligatoire et facile à oublier : le certificat est
	// chargé une fois, à l'ouverture de l'écouteur TLS. Sans redémarrage, le
	// serveur continue de présenter l'ancien et le diagnostic repart à zéro.
	fmt.Fprintf(&b, "⚠ Redémarrez le serveur : le certificat est chargé au démarrage de %s.\n", info.service)
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
	case "web", "web_server", "portail", "sso":
		return duckykey.WebServerCertName
	case "api", "api_server", "rest":
		return duckykey.APIServerCertName
	case "all", "tous", "tout":
		return "all"
	default:
		return strings.TrimSpace(v)
	}
}

func helpText() string {
	return `Utilisation : vlt certificate <sous-commande>

  list                    certificats en base et ce qu'ils couvrent
  show [ldaps]            détail, défauts constatés, et PEM à distribuer
  fingerprint             empreinte de la clé du core, attendue par les agents
  regenerate <cible>      régénère un certificat et le remplace en base
      ldaps               écouteur LDAPS
      web                 portail web
      api                 API REST
      all                 les trois
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
