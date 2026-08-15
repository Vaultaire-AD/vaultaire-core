package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// Vérificateurs du magasin de confiance et de la résolution DNS.
//
// Quatrième lot du point 4. Les deux modules ont la même forme : l'appliqueur
// dépose un fichier SOURCE, puis lance un outil qui en tire un état COMPILÉ, et
// c'est cet état compilé qui sert — pas le fichier.
//
// Le scan des fichiers surveille la source. Ce lot surveille le résultat.
//
// # Deux candidats de la liste ne sont PAS ici
//
// `package_repo` et `ssh_known_hosts` étaient sur la liste du point 44. Voir en
// fin de fichier : ils n'ajoutent rien au scan des fichiers, et le prix serait
// une analyse fragile de sorties qui changent d'une version à l'autre.

const (
	// CheckCADansMagasin : Target est le nom de la CA, Expect son empreinte
	// SHA-256, ou « absent ».
	CheckCADansMagasin = "ca_trust"
	// CheckDNSServers : Target est « global », Expect la liste attendue.
	CheckDNSServers = "dns_servers"
)

func init() {
	registerChecker(CheckCADansMagasin, verifierCADansMagasin)
	registerChecker(CheckDNSServers, verifierServeursDNS)
}

// --- magasin de confiance ---------------------------------------------------

// magasinsCompiles sont les bundles que les bibliothèques TLS lisent réellement.
//
// Ce ne sont PAS les répertoires où l'appliqueur dépose le certificat : ceux-là
// sont la source, ceux-ci le résultat de `update-ca-trust` ou
// `update-ca-certificates`. C'est toute la raison d'être de ce vérificateur.
var magasinsCompiles = []string{
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL, Rocky
	"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu
}

// verifierCADansMagasin constate qu'une CA est dans le magasin COMPILÉ.
//
// # Ce que cela ajoute au scan des fichiers
//
// L'appliqueur dépose le certificat puis régénère le magasin, et il échoue
// proprement si la régénération échoue — il retire même le fichier pour ne pas
// laisser croire à un succès partiel. À l'instant de l'application, tout va bien.
//
// Ce qui arrive ensuite lui échappe :
//
//   - la CA est mise en LISTE NOIRE (`/etc/pki/ca-trust/source/blacklist/`) : le
//     fichier source est intact, et la CA n'est plus reconnue par rien ;
//   - sur Debian, la CA est retirée de `/etc/ca-certificates.conf` : même chose ;
//   - le magasin est régénéré depuis un état où le fichier n'était pas encore là,
//     puis plus jamais.
//
// Dans les trois cas, le scan des fichiers voit une source intacte et déclare la
// machine conforme, alors qu'aucune connexion TLS ne fait confiance à cette CA.
//
// # Pourquoi une EMPREINTE et pas le texte du certificat
//
// `update-ca-trust` réécrit les certificats qu'il agrège : longueur de ligne,
// fins de ligne, ordre dans le bundle, et parfois un en-tête de commentaire.
// Chercher le texte déposé dans le bundle échouerait sur une machine
// parfaitement conforme.
//
// L'empreinte porte sur le DER — le contenu binaire du certificat — qui ne
// change pas, quelle que soit la mise en forme du PEM qui l'enveloppe. C'est la
// même raison qui fait hacher le DER dans EmpreinteClePublique, côté core.
func verifierCADansMagasin(c SystemCheck) (bool, string, error) {
	attendue := strings.ToLower(strings.TrimSpace(c.Expect))
	veutPresente := attendue != "absent"

	magasin, trouve := magasinCompile()
	if !trouve {
		return false, "", fmt.Errorf("aucun magasin de confiance compile trouve sur cette machine")
	}

	contenu, err := os.ReadFile(magasin)
	if err != nil {
		return false, "", fmt.Errorf("lecture de %s : %v", magasin, err)
	}

	if veutPresente && attendue == "" {
		// Empreinte vide : état écrit par une version qui ne la portait pas.
		// Rien à comparer — silence plutôt qu'un écart inventé.
		return true, "", nil
	}

	presente := empreinteDansMagasin(contenu, attendue)
	if presente == veutPresente {
		return true, "", nil
	}
	if veutPresente {
		return false, "CA " + c.Target + " absente du magasin de confiance compile (" +
			magasin + ") — le fichier source est en place mais aucune connexion TLS " +
			"ne fait confiance a cette autorite", nil
	}
	return false, "CA " + c.Target + " toujours dans le magasin de confiance alors " +
		"que la politique la retire", nil
}

// magasinCompile rend le premier bundle présent sur la machine.
func magasinCompile() (string, bool) {
	for _, chemin := range magasinsCompiles {
		if info, err := os.Stat(chemin); err == nil && !info.IsDir() {
			return chemin, true
		}
	}
	return "", false
}

// empreinteDansMagasin cherche une empreinte parmi les certificats d'un bundle.
//
// Le bundle est parcouru bloc par bloc avec `pem.Decode`, et non par recherche
// de texte : c'est ce qui rend la comparaison insensible à la mise en forme.
//
// Les blocs qui ne sont pas des certificats sont ignorés plutôt que refusés — un
// bundle peut porter des commentaires et, sur certaines distributions, des
// blocs « TRUSTED CERTIFICATE ».
func empreinteDansMagasin(bundle []byte, empreinte string) bool {
	empreinte = strings.ToLower(strings.TrimSpace(empreinte))
	if empreinte == "" {
		return false
	}
	reste := bundle
	for {
		var bloc *pem.Block
		bloc, reste = pem.Decode(reste)
		if bloc == nil {
			return false
		}
		if !strings.Contains(bloc.Type, "CERTIFICATE") || len(bloc.Bytes) == 0 {
			continue
		}
		if EmpreinteCertificat(bloc.Bytes) == empreinte {
			return true
		}
	}
}

// EmpreinteCertificat rend l'empreinte SHA-256 du DER d'un certificat.
//
// Exportée parce que l'appliqueur la calcule à l'application et que le
// vérificateur la recalcule à la lecture : les deux DOIVENT employer la même
// fonction, sinon la comparaison échoue toujours et le parc entier paraît
// dériver.
func EmpreinteCertificat(der []byte) string {
	somme := sha256.Sum256(der)
	return hex.EncodeToString(somme[:])
}

// EmpreintePEM rend l'empreinte du premier certificat d'un bloc PEM.
//
// Rend « » si le texte ne contient aucun certificat lisible. L'appliqueur a déjà
// vérifié la présence d'un « BEGIN CERTIFICATE » ; cette fonction ne redouble pas
// ce contrôle, elle constate seulement qu'il est décodable.
func EmpreintePEM(texte string) string {
	reste := []byte(texte)
	for {
		var bloc *pem.Block
		bloc, reste = pem.Decode(reste)
		if bloc == nil {
			return ""
		}
		if strings.Contains(bloc.Type, "CERTIFICATE") && len(bloc.Bytes) > 0 {
			return EmpreinteCertificat(bloc.Bytes)
		}
	}
}

// --- résolution DNS ---------------------------------------------------------

// verifierServeursDNS constate les serveurs DNS GLOBAUX de systemd-resolved.
//
// # Ce que cela ajoute au scan des fichiers
//
// Le fichier `/etc/systemd/resolved.conf.d/99-vaultaire-gpo.conf` est surveillé.
// Comme pour le temps, il décrit ce que resolved devrait lire — pas ce qu'il a
// lu. Un `resolvectl dns` posé à la main, un second fichier de configuration
// chargé après celui de la GPO, un service jamais redémarré depuis l'écriture :
// le fichier reste intact et la machine interroge d'autres serveurs.
//
// # Ce que ce vérificateur NE constate PAS, et c'est important
//
// Que la machine résout RÉELLEMENT par ces serveurs. Un DNS posé sur une
// INTERFACE — typiquement par DHCP — prime sur le global pour les requêtes qui
// passent par cette interface.
//
// Ce n'est pas une dérive de ce module : le module fixe le DNS global, et le DNS
// global est bien celui qu'il a fixé. Signaler un écart parce qu'un bail DHCP
// pose un résolveur reviendrait à signaler une dérive sur une machine dont la
// configuration est exactement celle demandée — et qu'aucune réapplication ne
// corrigerait.
//
// Couvrir ce cas demanderait un module qui décide de la politique par interface,
// ce qui n'existe pas. Le jour où il existera, il aura son propre vérificateur.
func verifierServeursDNS(c SystemCheck) (bool, string, error) {
	if !commandExists("resolvectl") {
		// systemd-resolved absent. L'appliqueur ne peut pas avoir abouti — il
		// échoue quand le redémarrage du service échoue — donc cette attente
		// vient d'une machine qui a changé depuis. On ne sait rien constater.
		return false, "", fmt.Errorf("resolvectl absent de cette machine")
	}

	sortie, err := runCommand("resolvectl", "dns")
	if err != nil {
		return false, "", fmt.Errorf("serveurs DNS illisibles : %v", err)
	}

	constates := serveursDNSGlobaux(sortie)
	attendus := serveursNTP(c.Expect) // même découpage : virgules ou espaces

	if len(attendus) == 0 {
		return true, "", nil
	}
	if len(constates) == 0 {
		return false, "aucun serveur DNS global configure — la politique en demande " +
			strings.Join(attendus, ", "), nil
	}
	if egalesIgnorantLOrdre(attendus, constates) {
		return true, "", nil
	}
	return false, ecartConstate("serveurs DNS globaux",
		strings.Join(attendus, ","), strings.Join(constates, ",")), nil
}

// serveursDNSGlobaux extrait la ligne « Global: » de la sortie de resolvectl.
//
//	Global: 10.0.0.1 10.0.0.2
//	Link 2 (eth0): 192.168.1.1
//
// Seule la ligne globale est lue. Les lignes « Link » décrivent des résolveurs
// posés par interface, que ce module ne fixe pas — les agréger ferait comparer
// des serveurs venus d'un bail DHCP à ceux de la politique, donc signaler une
// dérive permanente sur une machine correctement configurée.
//
// L'absence de ligne « Global: » rend une liste vide : resolved n'a aucun
// résolveur global, ce qui EST une dérive quand la politique en demande.
func serveursDNSGlobaux(sortie string) []string {
	for _, ligne := range strings.Split(sortie, "\n") {
		ligne = strings.TrimSpace(ligne)
		valeur, ok := strings.CutPrefix(ligne, "Global:")
		if !ok {
			continue
		}
		return serveursNTP(valeur)
	}
	return nil
}

// --- ce que ce lot refuse de vérifier ---------------------------------------

// # `package_repo` : le scan des fichiers le couvre déjà
//
// Le candidat paraissait bon — « un dépôt désactivé à la main n'est vu par
// rien ». C'est faux, et c'est ce que l'examen a montré.
//
// `dnf config-manager --set-disabled` écrit `enabled=0` DANS le fichier `.repo`
// déposé par la GPO. Le scan des fichiers compare le hachage : il le voit. Côté
// apt, désactiver un dépôt revient à retirer le fichier de `sources.list.d/`,
// et le scan voit une disparition.
//
// Un vérificateur n'ajouterait donc que le cas d'un second fichier déclarant le
// même identifiant de dépôt — que yum signale déjà comme un doublon — au prix
// d'une analyse de `dnf repolist` dont le format diffère entre dnf4 et dnf5, et
// de `apt-cache policy` dont la sortie n'a jamais été pensée pour être lue par
// un programme.
//
// Le rapport entre ce qu'on gagne et ce qu'on risque de déclarer de travers ne
// le justifie pas.
//
// # `ssh_known_hosts` : rien ne masque ce fichier
//
// Même raisonnement, plus court. `/etc/ssh/ssh_known_hosts` est le chemin que
// `GlobalKnownHostsFile` désigne par défaut, et le scan le surveille. Il n'y a
// pas d'état compilé, pas de service à recharger, pas de second fichier qui
// prendrait le dessus.
//
// L'idée d'un « second fichier qui le masque » venait d'une analogie avec les
// fragments de configuration — elle ne s'applique pas ici.
