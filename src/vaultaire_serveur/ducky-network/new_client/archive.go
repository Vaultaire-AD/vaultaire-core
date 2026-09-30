package newclient

// L'archive d'installation d'une machine — TO-DO 82.
//
// # Le défaut que cela ferme
//
// Créer une machine produisait son identité sur le DISQUE DU CORE, et s'arrêtait
// là. Pour l'installer, il fallait un `docker exec` ou un `ssh` sur le core afin
// d'aller chercher trois fichiers, puis une commande de plus pour relever
// l'empreinte de la clé du core, et la retaper sur le poste. Depuis le portail,
// c'était pire : la page annonçait « Machine créée, identifiant … » et ne
// donnait rien.
//
// Pire encore, trois des fichiers NÉCESSAIRES n'étaient produits que par le
// chemin `-join` — le déploiement SSH — donc jamais pour une machine créée
// autrement : l'empreinte du core, la clé de signature des politiques et la
// liste des cores. Une machine créée depuis le portail naissait incomplète, et
// rien ne le disait.
//
// # Ce que le modèle de confiance devient : rien de neuf
//
// La clé privée d'un client BASIC naît sur le core et voyage déjà — par SCP
// avec `-join`, ou sur une clé USB. L'archive ne change pas cela, elle change le
// CANAL : HTTPS depuis une session de portail authentifiée, au lieu de SSH ou
// d'un support physique. C'est un canal de moins à improviser.
//
// Un client SERVICE, lui, n'a rien à faire ici et n'y entre pas : sa paire naît
// sur son propre hôte au moment de l'enrôlement, et sa clé privée ne doit jamais
// exister ailleurs. ConstruireArchive le REFUSE explicitement — c'est un
// invariant du produit, pas une préférence.

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	autoaddclientgo "vaultaire/ducky-network/new_client/AUTO_ADD_client.go"

	"vaultaire/core/clienttype"
	dbclients "vaultaire/core/database/db_clients"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	duckykey "vaultaire/ducky-network/key_management"
)

// Les systèmes pour lesquels une archive se compose.
//
// Ce choix ne dit PAS sur quoi la machine tourne : il dit quoi mettre dans
// l'archive. La colonne `os` de l'inventaire, elle, est renseignée par l'agent
// lui-même une fois qu'il parle — et elle doit le rester, sous peine d'afficher
// ce qu'on a coché plutôt que ce qui tourne.
const (
	SystemeWindows = "windows"
	SystemeLinux   = "linux"
)

// SystemeValide normalise et contrôle le système demandé.
func SystemeValide(systeme string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(systeme)) {
	case "", SystemeLinux:
		// Linux par défaut : c'est le système du parc, et l'archive la plus
		// complète. Se tromper par défaut vers « plus de fichiers » laisse un
		// fichier inutile sur un poste ; l'inverse laisse un agent muet.
		return SystemeLinux, nil
	case SystemeWindows:
		return SystemeWindows, nil
	default:
		return "", fmt.Errorf("système %q inconnu : attendu « linux » ou « windows »", systeme)
	}
}

// RepertoireDeLaMachine rend le répertoire d'identité d'une machine sur le core.
func RepertoireDeLaMachine(computeurID string) string {
	return filepath.Join(storage.Client_Conf_path, "clientsoftware", computeurID)
}

// fichiersDeLArchive dit ce que porte une archive, par système.
//
// Séparé pour être lisible d'un coup d'œil ET éprouvable : la composition est
// la seule chose que l'on puisse vérifier sans base de données, et c'est celle
// qui se trompe en silence — un fichier oublié ne casse rien à la fabrication,
// il produit un agent dégradé des semaines plus tard.
//
// La clé de signature des politiques ne part QUE vers Linux : l'agent Windows
// ignore délibérément les trames de politique (05/06). La lui livrer ne
// l'exposerait à rien, mais poserait dans son dossier un fichier dont personne
// ne saurait dire à quoi il sert. Une archive doit se lire.
// Les deux fichiers que l'archive ne peut pas reconstituer.
//
// La clé privée n'existe QUE là : la base ne porte que la publique. Nommés une
// fois, ici, et repris partout — un littéral recopié dans le lisez-moi ferait
// mentir la documentation au premier renommage, sans qu'aucun test ne bouge.
const (
	NomIdentite  = "client_software.yaml"
	NomClePrivee = "private_key.pem"
)

// FichiersDIdentite rend ce qui doit impérativement être présent.
func FichiersDIdentite() []string { return []string{NomIdentite, NomClePrivee} }

func fichiersDeLArchive(systeme string) []string {
	fichiers := []string{
		NomIdentite,
		NomClePrivee,
		duckykey.CoreFingerprintFileName,
		autoaddclientgo.NomConfClient,
	}
	if systeme == SystemeLinux {
		fichiers = append(fichiers, duckykey.GPOPublicKeyFileName)
	}
	return fichiers
}

// ConstruireArchive fabrique le zip d'installation d'une machine.
//
// Rend les octets et le nom de fichier proposé. Rien n'est écrit sur le disque
// hors des fichiers d'identité, qui y sont de toute façon.
//
// # Pourquoi un zip et pas un tar
//
// Windows décompresse le zip nativement, le tar non — et c'est précisément le
// poste Windows qui motive cette archive. Un administrateur qui doit d'abord
// installer 7-Zip pour lire l'archive qui devait lui simplifier la vie n'a rien
// gagné.
//
// # Pourquoi les fichiers compagnons sont RÉÉCRITS à chaque fois
//
// L'empreinte du core, la clé de signature et la liste des cores changent avec
// le cluster : un core ajouté, une clé renouvelée. Les recopier d'un dépôt figé
// livrerait une liste périmée à une machine installée six mois plus tard. Ils
// sont donc produits au moment de la demande, par les mêmes fonctions que le
// chemin `-join` — une seule définition de ce qu'un agent doit recevoir.
func ConstruireArchive(db *sql.DB, computeurID, systeme string) ([]byte, string, error) {
	computeurID = strings.TrimSpace(computeurID)
	if computeurID == "" {
		return nil, "", fmt.Errorf("identifiant de machine vide")
	}
	systeme, err := SystemeValide(systeme)
	if err != nil {
		return nil, "", err
	}

	// LE contrôle : un service n'est pas exportable.
	//
	// Fait sur le TYPE EN BASE et non sur ce que l'appelant annonce : c'est le
	// core qui sait ce qu'il a créé. Un client inconnu est refusé au même
	// endroit, ce qui évite de fabriquer une archive à partir d'un répertoire
	// que quelqu'un aurait posé à la main.
	typeClient, err := dbclients.Get_Client_Type(db, computeurID)
	if err != nil {
		return nil, "", fmt.Errorf("machine %s introuvable : %w", computeurID, err)
	}
	// Fail-CLOSED sur un type inconnu, et pas seulement sur un service.
	//
	// IsService rend false pour un type hors catalogue — donc « pas un
	// service », donc export autorisé. Or `logiciel_type` est une colonne libre
	// héritée, et la migration qui la range est opt-in : des lignes hors
	// catalogue existent. Un type qu'on ne sait pas nommer n'est pas un type
	// qu'on sait exporter.
	definition, connu := clienttype.Lookup(typeClient)
	if !connu {
		return nil, "", fmt.Errorf(
			"%s porte le type %q, absent du catalogue : refus par précaution. "+
				"Voir deployments/pre-prod/scripts/migrate-clienttype.sh",
			computeurID, typeClient)
	}
	if definition.Family == clienttype.FamilyService {
		return nil, "", fmt.Errorf(
			"%s est un client service (%s) : sa clé privée naît sur son propre hôte et ne doit "+
				"jamais voyager. Il s'enrôle avec « vlt enroll create --type %s »",
			computeurID, typeClient, typeClient)
	}

	repertoire := RepertoireDeLaMachine(computeurID)

	// L'identité doit ÊTRE LÀ. Elle n'est pas reconstructible : la clé privée
	// n'existe que dans ce fichier — la base ne porte que la publique. Un
	// répertoire effacé se solde donc par une machine à recréer, et il vaut
	// mieux le dire ici que livrer une archive amputée.
	identite := FichiersDIdentite()
	for _, nom := range identite {
		if _, err := os.Stat(filepath.Join(repertoire, nom)); err != nil {
			return nil, "", fmt.Errorf(
				"%s est introuvable pour %s : l'identité n'est plus sur ce core, "+
					"la machine est à recréer (la clé privée n'existe nulle part ailleurs)",
				nom, computeurID)
		}
	}

	// Les compagnons, produits maintenant. Leur échec n'interrompt PAS : un
	// agent sans empreinte fonctionne — il accepte la première clé reçue et le
	// journalise —, un agent sans liste de cores se rabat sur celui qu'on lui
	// donne à l'installation. Refuser l'archive pour autant transformerait un
	// durcissement en panne de déploiement, ce qui pousserait à s'en passer.
	// C'est la même règle que le chemin `-join`, et elle doit le rester.
	manquants := []string{}
	if err := duckykey.EcrireEmpreintePourClient(repertoire); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeCertLoad,
			"archive: empreinte du core non produite pour "+computeurID+" : "+err.Error()+
				" — l'agent acceptera la première clé reçue")
		manquants = append(manquants, duckykey.CoreFingerprintFileName)
	}
	// Le COMPTE est lu, pas seulement l'erreur.
	//
	// EcrireConfClient rend (0, nil) — un succès — quand aucun core n'est
	// exposé et en ligne, et EFFACE alors le fichier existant pour qu'une
	// installation ne reparte pas sur une liste périmée. Ne regarder que
	// l'erreur laissait donc sortir une archive sans client_conf.json, sans
	// avertissement, et avec un lisez-moi qui l'annonçait quand même — alors
	// que c'est le fichier dont l'absence est BLOQUANTE pour l'agent Windows.
	// Le chemin `-join` traite ce cas à part ; il fallait le traiter aussi ici.
	if n, err := autoaddclientgo.EcrireConfClient(db, repertoire); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeDBQuery,
			"archive: liste des cores non produite pour "+computeurID+" : "+err.Error())
		manquants = append(manquants, autoaddclientgo.NomConfClient)
	} else if n == 0 {
		logs.Write_Log("WARNING", "archive: aucun core exposé et en ligne pour "+computeurID+
			" — l'archive partira sans "+autoaddclientgo.NomConfClient)
		manquants = append(manquants, autoaddclientgo.NomConfClient)
	}

	if systeme == SystemeLinux {
		if err := duckykey.EcrireClePolitiquePourClient(repertoire); err != nil {
			logs.Write_LogCode("WARNING", logs.CodeCertLoad,
				"archive: clé de signature des politiques non produite pour "+computeurID+" : "+
					err.Error()+" — l'agent ne vérifiera pas les signatures de politique")
			manquants = append(manquants, duckykey.GPOPublicKeyFileName)
		}
	}
	fichiers := fichiersDeLArchive(systeme)

	var tampon bytes.Buffer
	zw := zip.NewWriter(&tampon)

	// Le dossier porté par l'archive est nommé d'après la machine : décompressée
	// à côté d'une autre, elle ne l'écrase pas, et le dossier dit de qui il est.
	racine := "vaultaire-" + computeurID

	obligatoire := map[string]bool{}
	for _, nom := range FichiersDIdentite() {
		obligatoire[nom] = true
	}

	for _, nom := range fichiers {
		contenu, err := os.ReadFile(filepath.Join(repertoire, nom))
		if err != nil {
			// Un COMPAGNON manquant se saute : il a été signalé plus haut, et
			// le lisez-moi le nommera.
			//
			// Un fichier d'IDENTITÉ, lui, fait échouer — même s'il a passé le
			// contrôle d'existence plus haut. Ce contrôle est un os.Stat, la
			// lecture un os.ReadFile : ce n'est pas la même chose, et entre les
			// deux le répertoire a pu changer. Sans ce refus, on livrait une
			// archive valide, sans erreur, SANS clé privée, dont le lisez-moi
			// annonçait la clé privée.
			if obligatoire[nom] {
				return nil, "", fmt.Errorf(
					"%s illisible pour %s : %w — archive non composée", nom, computeurID, err)
			}
			continue
		}

		// Le MODE voyage avec le fichier.
		//
		// zw.Create n'en pose aucun : la clé privée s'extrayait en 0644, lisible
		// par tout compte du poste entre l'extraction et l'installation. Le
		// chemin `-join` produit 0600 et le script d'installation applique 0400 ;
		// l'archive ne pouvait pas être la seule voie à livrer la clé ouverte.
		mode := os.FileMode(0644)
		if nom == NomClePrivee {
			mode = 0600
		}
		entete := &zip.FileHeader{
			// path.Join et non filepath.Join : la spécification ZIP impose la
			// barre oblique. Identique sur un core Linux, faux en principe — et
			// c'est le genre d'écart qui se découvre le jour d'un portage.
			Name:   path.Join(racine, nom),
			Method: zip.Deflate,
		}
		entete.SetMode(mode)
		f, err := zw.CreateHeader(entete)
		if err != nil {
			return nil, "", fmt.Errorf("archive: %s : %w", nom, err)
		}
		if _, err := f.Write(contenu); err != nil {
			return nil, "", fmt.Errorf("archive: écriture de %s : %w", nom, err)
		}
	}

	// Un lisez-moi DANS l'archive.
	//
	// C'est le seul endroit où celui qui l'ouvre — des jours plus tard, sur une
	// autre machine, sans le portail sous les yeux — peut encore apprendre ce
	// qu'il tient, ce qui manque éventuellement, et ce que cela coûte.
	lisezmoi, err := zw.Create(path.Join(racine, "LISEZ-MOI.txt"))
	if err != nil {
		return nil, "", fmt.Errorf("archive: lisez-moi : %w", err)
	}
	if _, err := lisezmoi.Write([]byte(texteLisezMoi(computeurID, systeme, manquants))); err != nil {
		return nil, "", fmt.Errorf("archive: écriture du lisez-moi : %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, "", fmt.Errorf("archive: fermeture : %w", err)
	}

	nomFichier := fmt.Sprintf("vaultaire-%s-%s.zip", computeurID, systeme)
	logs.Write_Log("INFO", fmt.Sprintf(
		"archive: identité de %s composée pour %s (%d octets)", computeurID, systeme, tampon.Len()))
	return tampon.Bytes(), nomFichier, nil
}

// texteLisezMoi compose la note qui accompagne l'archive.
func texteLisezMoi(computeurID, systeme string, manquants []string) string {
	var b strings.Builder
	b.WriteString("Identite de la machine " + computeurID + " (" + systeme + ")\n")
	b.WriteString("====================================================\n\n")
	b.WriteString("CETTE ARCHIVE CONTIENT UNE CLE PRIVEE. Elle vaut l'identite de la\n")
	b.WriteString("machine sur le parc : qui la detient peut se faire passer pour elle.\n")
	b.WriteString("Ne la laissez pas dans un dossier de telechargement, et effacez-la une\n")
	b.WriteString("fois l'agent installe.\n\n")
	b.WriteString("Contenu :\n")
	b.WriteString("  " + NomIdentite + "    l'identite : identifiant et type\n")
	b.WriteString("  " + NomClePrivee + "         la cle privee de la machine (mode 0600)\n")
	b.WriteString("  " + duckykey.CoreFingerprintFileName + "    l'empreinte de la cle du core, pour que l'agent\n")
	b.WriteString("                          verifie la cle qu'il recevra au lieu de l'accepter\n")
	b.WriteString("                          sur parole\n")
	b.WriteString("  " + autoaddclientgo.NomConfClient + "        les cores a joindre\n")
	if systeme == SystemeLinux {
		b.WriteString("  " + duckykey.GPOPublicKeyFileName + "     la cle qui verifie la signature des politiques\n")
	}
	b.WriteString("\n")

	if len(manquants) > 0 {
		b.WriteString("ATTENTION — ces fichiers n'ont PAS pu etre produits :\n")
		for _, m := range manquants {
			b.WriteString("  - " + m + "\n")
		}
		b.WriteString("\nL'agent fonctionnera quand meme, en mode degrade :\n")
		b.WriteString("  sans core_key_fingerprint, il accepte la premiere cle du core qu'il\n")
		b.WriteString("  recoit, et le journalise ; sans client_conf.json, il faut lui donner\n")
		b.WriteString("  l'adresse du core a l'installation ; sans gpo_signing_key.pem, il ne\n")
		b.WriteString("  verifie pas la signature des politiques.\n")
		b.WriteString("Relancer l'export plus tard produira une archive complete si la cause\n")
		b.WriteString("du probleme a disparu.\n\n")
	}

	switch systeme {
	case SystemeWindows:
		b.WriteString("Installation :\n")
		b.WriteString("  1. decompressez l'archive de l'agent Windows sur le poste ;\n")
		b.WriteString("  2. dans une invite PowerShell administrateur, depuis ce dossier :\n")
		b.WriteString("       .\\install.ps1 -Identite <chemin du .zip telecharge>\n")
		b.WriteString("\n")
		b.WriteString("  -Identite prend le .zip TEL QUEL : ne le decompressez pas. Il est\n")
		b.WriteString("  extrait dans un dossier temporaire, efface aussitot l'identite en\n")
		b.WriteString("  place — une cle privee decompressee n'a rien a faire dans le dossier\n")
		b.WriteString("  des telechargements. Un dossier deja decompresse est accepte aussi.\n")
		b.WriteString("\n")
		b.WriteString("  install.ps1 y prend l'identite, l'empreinte et la liste des cores :\n")
		b.WriteString("  il ne pose plus aucune de ces questions.\n")
	default:
		b.WriteString("Installation :\n")
		b.WriteString("  deposez ces fichiers dans /etc/vaultaire_client/.ssh/ sur la machine\n")
		b.WriteString("  (" + autoaddclientgo.NomConfClient + " va dans /etc/vaultaire_client/), puis lancez le\n")
		b.WriteString("  script d'installation du paquet de l'agent.\n")
		b.WriteString("\n")
		b.WriteString("  VERIFIEZ LES DROITS de la cle privee apres extraction :\n")
		b.WriteString("       chown root:root /etc/vaultaire_client/.ssh/" + NomClePrivee + "\n")
		b.WriteString("       chmod 400       /etc/vaultaire_client/.ssh/" + NomClePrivee + "\n")
		b.WriteString("  L'archive la porte en 0600, mais tous les outils d'extraction ne\n")
		b.WriteString("  respectent pas les modes du zip.\n")
		b.WriteString("  Le deploiement automatique « vlt create -c <oui|non> -join <hote> <user> »\n")
		b.WriteString("  fait tout cela seul, et reste la voie la plus simple sur un parc Linux.\n")
	}
	return b.String()
}
