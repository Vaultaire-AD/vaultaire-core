package serveurauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// Attestation de la clé publique du core.
//
// # Ce que ce fichier corrige
//
// La clé publique du core était récupérée par la trame `askkey`, sur un canal
// que rien n'authentifie, puis écrite sur disque et considérée comme acquise.
// C'est le modèle de confiance au premier usage — celui de SSH — et il porte la
// même faiblesse : quiconque répond à la place du core, à cet instant précis,
// devient le core pour cette machine, définitivement.
//
// La différence avec SSH tient à ce qu'il montre. SSH affiche l'empreinte et
// demande confirmation ; l'agent acceptait en silence. Personne ne pouvait donc
// remarquer une substitution, même en la cherchant.
//
// # Ce qui est ajouté
//
// Une empreinte attendue, déposée sur la machine par `vlt create -join` —
// c'est-à-dire par SSH, un canal déjà authentifié. La clé reçue est comparée à
// cette empreinte avant d'être écrite.
//
// L'empreinte n'est pas un secret : elle ne sert qu'à reconnaître, et sa
// divulgation n'aide personne. C'est son INTÉGRITÉ qui compte, d'où le canal
// authentifié pour la transporter.
//
// # Ce que cela ne couvre pas
//
// Une machine sur laquelle aucune empreinte n'a été déposée reste en confiance
// au premier usage. Le choix est délibéré : refuser tout démarrage sans
// empreinte rendrait impossible l'installation manuelle d'un agent, et le
// remède serait pire.
//
// La distinction apparaît dans le journal — « empreinte vérifiée » ou
// « aucune empreinte connue, acceptation en confiance ». Un parc où la seconde
// ligne apparaît est un parc qu'on peut corriger ; un parc où rien n'apparaît
// est un parc dont on ignore l'état.

// FingerprintFileName est le nom du fichier d'empreinte, déposé à côté de la
// clé qu'il atteste.
const FingerprintFileName = "core_key_fingerprint"

// CoreFingerprintPath rend le chemin du fichier d'empreinte.
func CoreFingerprintPath() string {
	return storage.CheminDansKeyPath(FingerprintFileName)
}

// EmpreinteClePublique calcule l'empreinte d'une clé publique au format PEM.
//
// # Pourquoi hacher le DER et non le PEM
//
// Le PEM est une enveloppe texte : sauts de ligne, espaces de fin, présence ou
// non d'un saut final, terminaisons CRLF sur les fichiers passés par Windows.
// Toutes ces variations laissent la clé identique et changeraient le haché.
//
// Une empreinte qui dépend de la mise en forme produirait des refus sur une clé
// pourtant correcte — le pire des résultats, puisque le message dirait
// « la clé du core a changé » alors qu'elle n'a pas bougé.
//
// Le DER est la forme binaire canonique. C'est aussi ce que hache OpenSSH, d'où
// le préfixe « SHA256: » et l'encodage base64 sans remplissage : un
// administrateur habitué à `ssh-keygen -lf` reconnaît la forme.
func EmpreinteClePublique(pemContent string) (string, error) {
	bloc, _ := pem.Decode([]byte(pemContent))
	if bloc == nil {
		return "", fmt.Errorf("clé publique illisible : ce n'est pas du PEM")
	}
	if len(bloc.Bytes) == 0 {
		return "", fmt.Errorf("clé publique vide")
	}
	somme := sha256.Sum256(bloc.Bytes)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(somme[:]), nil
}

// EmpreintesAttendues lit les empreintes déposées sur la machine.
//
// # Pourquoi une LISTE et non une empreinte
//
// Un parc peut compter plusieurs cores, et un agent doit pouvoir basculer de
// l'un à l'autre — c'est tout l'objet de la découverte de service. Avec une
// empreinte unique, distribuer une liste de cores ne servait à rien : l'agent
// aurait refusé tous ceux qu'il ne connaissait pas, c'est-à-dire tous sauf un.
//
// Rend une liste vide sans erreur quand le fichier n'existe pas : c'est le cas
// d'une installation qui n'est pas passée par `-join`, et non une anomalie.
//
// L'ordre du fichier est conservé. La PREMIÈRE ligne est celle déposée à
// l'installation, par un canal authentifié ; les suivantes ont été apprises. La
// distinction ne change rien à la vérification — toutes valent — mais elle rend
// le fichier lisible pour qui l'inspecte après coup.
func EmpreintesAttendues() ([]string, error) {
	brut, err := os.ReadFile(CoreFingerprintPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var out []string
	vues := map[string]bool{}
	// Le fichier peut avoir été édité à la main, ou déposé avec un saut de
	// ligne final selon l'outil qui l'écrit. On tolère les deux, et les
	// commentaires, pour qu'il reste lisible.
	for _, ligne := range strings.Split(string(brut), "\n") {
		ligne = strings.TrimSpace(strings.TrimSuffix(ligne, "\r"))
		if ligne == "" || strings.HasPrefix(ligne, "#") {
			continue
		}
		// Une ligne qui n'a pas la forme attendue est IGNORÉE, pas fatale. Le
		// fichier est éditable à la main ; une faute de frappe ne doit pas faire
		// perdre les empreintes valides qui l'entourent, ce qui ferait retomber
		// la machine en confiance au premier usage — l'inverse du but.
		if !strings.HasPrefix(ligne, "SHA256:") {
			continue
		}
		if vues[ligne] {
			continue
		}
		vues[ligne] = true
		out = append(out, ligne)
	}
	return out, nil
}

// EmpreinteAttendue rend la première empreinte, ou la chaîne vide.
//
// Conservée pour les appelants qui n'ont besoin que d'une valeur à AFFICHER —
// un message d'erreur, un diagnostic. Ne jamais s'en servir pour VÉRIFIER : elle
// ignorerait les empreintes apprises, et refuserait des cores légitimes.
func EmpreinteAttendue() (string, error) {
	liste, err := EmpreintesAttendues()
	if err != nil || len(liste) == 0 {
		return "", err
	}
	return liste[0], nil
}

// MaxEmpreintes borne la liste.
//
// Sans borne, chaque core rencontré ajouterait une ligne, indéfiniment. Un fichier
// de confiance qui grossit tout seul finit par ne plus rien attester : personne
// ne relit trente empreintes pour savoir laquelle n'a rien à y faire.
//
// La valeur est large au regard d'un cluster réel, et l'atteindre est un signal
// en soi — d'où le refus explicite plutôt qu'une éviction silencieuse de la plus
// ancienne, qui retirerait justement celle déposée à l'installation.
const MaxEmpreintes = 16

// ApprendreEmpreinte ajoute une empreinte à la liste de confiance.
//
// # La règle : on n'apprend QUE depuis une confiance existante
//
// L'appelant doit se trouver dans une session déjà vérifiée. Cette fonction ne
// peut pas le constater elle-même — elle ne voit pas la session — mais elle
// refuse le cas où la question ne se pose pas : une liste VIDE signifie que la
// machine n'a aucun point d'ancrage, et apprendre y reviendrait à faire de la
// confiance au premier usage sous un autre nom.
//
// Un seul appelant existe, dans le traitement de `04_04` : la liste de nœuds
// arrive par une session dont la clé du core a été vérifiée à l'ouverture.
//
// # La limite, écrite parce qu'elle est réelle
//
// TOUT CORE DE CONFIANCE PEUT AJOUTER DE LA CONFIANCE. Un core compromis peut
// faire apprendre à tout le parc l'empreinte d'une machine qu'il contrôle.
//
// C'est le prix d'un parc où les agents suivent le cluster sans intervention
// manuelle. L'alternative — déposer chaque empreinte par `-join` — ne se tient
// que sur un parc dont la liste de cores ne bouge jamais, et rendrait l'ajout
// d'un core impossible sans repasser sur chaque machine.
//
// Ce qui borne le risque est ailleurs : un core compromis a déjà les clés du
// domaine. L'empreinte n'est pas ce qui le retient.
//
// Rend « appris » à faux quand l'empreinte était déjà connue — cas courant, ce
// n'est pas une erreur.
func ApprendreEmpreinte(empreinte string) (appris bool, err error) {
	if !strings.HasPrefix(empreinte, "SHA256:") {
		return false, fmt.Errorf("empreinte %q : forme attendue « SHA256:... »", empreinte)
	}

	connues, err := EmpreintesAttendues()
	if err != nil {
		return false, fmt.Errorf("empreintes connues illisibles : %w", err)
	}
	if len(connues) == 0 {
		return false, fmt.Errorf(
			"aucune empreinte de référence sur cette machine : il n'y a pas de "+
				"confiance à étendre. Déployez l'agent avec « vlt create -join » pour "+
				"déposer la première empreinte dans %s", CoreFingerprintPath())
	}
	for _, c := range connues {
		if c == empreinte {
			return false, nil
		}
	}
	if len(connues) >= MaxEmpreintes {
		return false, fmt.Errorf(
			"%d empreintes déjà connues (maximum %d) : %s n'est pas ajoutée. "+
				"Vérifiez le contenu de %s — un fichier de confiance qui grossit "+
				"sans raison n'atteste plus rien",
			len(connues), MaxEmpreintes, empreinte, CoreFingerprintPath())
	}

	// Ajout en QUEUE, avec la date. La première ligne reste celle de
	// l'installation : c'est la seule dont on sait par quel canal elle est
	// arrivée, et l'ordre est ce qui le dit.
	ligne := empreinte + "\n"
	f, err := os.OpenFile(CoreFingerprintPath(), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return false, fmt.Errorf("ouverture de %s : %w", CoreFingerprintPath(), err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(ligne); err != nil {
		return false, fmt.Errorf("écriture dans %s : %w", CoreFingerprintPath(), err)
	}
	return true, nil
}

// ErrCleCoreInattendue signale une clé qui ne correspond pas à l'empreinte
// connue. Type distinct pour que l'appelant puisse la traiter à part : ce n'est
// pas une panne de réseau, et le message à afficher n'est pas le même.
type ErrCleCoreInattendue struct {
	// Attendues porte TOUTES les empreintes connues, pas seulement la première.
	//
	// Le message doit les montrer : sur un parc à plusieurs cores, n'en afficher
	// qu'une ferait chercher un écart entre la clé reçue et un core qui n'est
	// peut-être pas celui qu'on joint.
	Attendues []string
	Recue     string
}

func (e *ErrCleCoreInattendue) Error() string {
	attendues := "aucune"
	if len(e.Attendues) > 0 {
		attendues = strings.Join(e.Attendues, "\n                       ")
	}
	return fmt.Sprintf(
		"la clé publique du core ne correspond à aucune empreinte connue de cette machine.\n"+
			"  empreintes connues : %s\n"+
			"  empreinte reçue    : %s\n"+
			"\n"+
			"  Deux explications possibles, et elles n'appellent pas la même réponse :\n"+
			"\n"+
			"    1. Le core a changé de clé — après une réinstallation, une restauration\n"+
			"       de sauvegarde, ou une rotation volontaire. C'est le cas courant.\n"+
			"       Pour accepter la nouvelle clé sur CETTE machine :\n"+
			"           sudo rm %s %s\n"+
			"       puis redémarrer l'agent. Il réapprendra au prochain contact.\n"+
			"\n"+
			"    2. Quelqu'un répond à la place du core. Dans ce cas, effacer les\n"+
			"       fichiers ci-dessus revient à accepter l'imposteur.\n"+
			"\n"+
			"  Avant d'effacer quoi que ce soit : vérifiez sur le core que l'empreinte\n"+
			"  reçue est bien la sienne, avec « vlt certificate show core » ou\n"+
			"  « openssl pkey -pubin -in <clé> -outform DER | openssl dgst -sha256 -binary | base64 ».",
		e.Attendue, e.Recue,
		CoreFingerprintPath(), storage.CheminDansKeyPath("serveurpublickey.pem"))
}

// VerifierCleCore compare la clé reçue à l'empreinte connue.
//
// Trois issues :
//
//	nil, ""      la clé correspond à l'empreinte attendue
//	nil, motif   aucune empreinte connue : acceptée, avec la raison à journaliser
//	erreur       la clé ne correspond pas — elle ne doit PAS être écrite
//
// Le second cas rend une raison plutôt qu'un simple booléen pour que
// l'appelant journalise POURQUOI il a accepté sans vérifier. Une acceptation
// silencieuse est ce qui a permis au défaut de passer inaperçu jusqu'ici.
func VerifierCleCore(pemRecu string) (avertissement string, err error) {
	recue, err := EmpreinteClePublique(pemRecu)
	if err != nil {
		return "", err
	}

	attendues, err := EmpreintesAttendues()
	if err != nil {
		// Lecture impossible alors que le fichier existe : droits, disque. On
		// refuse plutôt que de poursuivre — un défaut de lecture ne doit pas
		// se traduire par un affaiblissement silencieux de la vérification.
		return "", fmt.Errorf("empreintes attendues illisibles (%s) : %w", CoreFingerprintPath(), err)
	}

	if len(attendues) == 0 {
		return fmt.Sprintf(
			"aucune empreinte de référence sur cette machine (%s absent) : "+
				"la clé du core est acceptée en confiance au premier usage, empreinte %s. "+
				"Pour attester les prochaines connexions, déployez l'agent avec « vlt create -join ».",
			CoreFingerprintPath(), recue), nil
	}

	// N'IMPORTE LAQUELLE des empreintes connues suffit.
	//
	// Le parcours va jusqu'au bout même après une correspondance : sortir tôt
	// ferait dépendre le temps de réponse du RANG de l'empreinte trouvée, ce que
	// la comparaison à temps constant juste en dessous existe précisément pour
	// éviter. La liste compte au plus MaxEmpreintes entrées, le coût est nul.
	correspond := 0
	for _, attendue := range attendues {
		// La valeur n'est pas secrète et l'attaque par mesure du temps n'est ici
		// guère praticable — mais une comparaison de chaînes ordinaire dans un
		// chemin d'authentification est le genre de détail qu'on recopie
		// ailleurs, où il comptera.
		correspond |= subtle.ConstantTimeCompare([]byte(attendue), []byte(recue))
	}
	if correspond != 1 {
		return "", &ErrCleCoreInattendue{Attendues: attendues, Recue: recue}
	}

	return "", nil
}

// CleLocaleConforme vérifie la clé du core DÉJÀ présente sur le disque.
//
// # Pourquoi cette fonction manquait, et ce que son absence a coûté
//
// La première version ne vérifiait qu'au moment de `askkey`, c'est-à-dire
// uniquement quand la clé était absente. Une clé déjà en place n'était jamais
// confrontée à l'empreinte.
//
// Le raisonnement paraissait solide : une clé écrite avait forcément été
// vérifiée à l'écriture. Il est faux, parce qu'il ne tient que pour les clés
// écrites APRÈS la mise en place du contrôle. Toutes celles déjà sur le parc y
// échappaient — et ce sont précisément celles dont on ne sait rien.
//
// Le cas s'est produit : une machine portait un `serveurpublickey.pem` obtenu
// d'un core dont la clé avait changé depuis. L'agent chiffrait donc sa poignée
// de main avec une clé que le core ne pouvait plus déchiffrer. Le core recevait
// une trame illisible et n'y répondait pas ; l'agent attendait, puis signalait :
//
//	Erreur lors de la lecture du header : EOF
//	Authentification serveur échouée sur 192.168.30.3:6666
//
// Rien dans ce message ne désignait la clé. L'empreinte était pourtant sur la
// machine, à côté du fichier fautif, et les comparer aurait donné la réponse
// immédiatement.
//
// # Pourquoi écarter la clé plutôt que refuser de démarrer
//
// L'empreinte change la nature du problème. Sans elle, redemander la clé serait
// dangereux : on accepterait ce qui répond. Avec elle, la clé redemandée sera
// confrontée à l'empreinte — donc un imposteur sera refusé.
//
// Écarter la clé non conforme est alors la bonne réponse : elle rétablit le
// service quand le core a légitimement changé de clé, et ne rétablit rien quand
// c'est un tiers qui répond. La sécurité vient de la vérification à la
// réception, pas du refus de reprendre.
//
// Sans empreinte, en revanche, on ne touche à rien : écarter une clé qu'on ne
// peut pas remplacer par mieux ne ferait qu'ouvrir la porte au premier venu.
//
// Rend :
//
//	true, motif   la clé est à écarter et à redemander
//	false, ""     rien à faire — conforme, absente, ou non vérifiable
func CleLocaleConforme() (aEcarter bool, motif string) {
	cheminCle := storage.CheminDansKeyPath("serveurpublickey.pem")

	contenu, err := os.ReadFile(cheminCle)
	if os.IsNotExist(err) {
		return false, "" // Absente : le chemin normal d'une première connexion.
	}
	if err != nil {
		return false, ""
	}

	attendues, err := EmpreintesAttendues()
	if err != nil || len(attendues) == 0 {
		// Pas d'empreinte, ou illisible : rien à quoi comparer. On ne touche
		// pas à une clé en place sur la foi de rien.
		return false, ""
	}
	attendue := strings.Join(attendues, ", ")

	presente, err := EmpreinteClePublique(string(contenu))
	if err != nil {
		// Le fichier existe mais n'est pas une clé lisible — tronqué, corrompu.
		// Il ne servira à rien ; autant le redemander.
		return true, fmt.Sprintf(
			"la clé du core présente sur cette machine est illisible (%s : %v) — "+
				"elle va être redemandée au core, et vérifiée contre les empreintes %s",
			cheminCle, err, attendue)
	}

	// N'IMPORTE LAQUELLE des empreintes connues rend la clé locale acceptable.
	//
	// Ne comparer qu'à la première écarterait la clé d'un core APPRIS à chaque
	// démarrage : l'agent la redemanderait, la revérifierait avec succès — la
	// vérification, elle, parcourt toute la liste — et la réécrirait. Une boucle
	// sans effet visible, sinon un aller-retour réseau à chaque cycle.
	for _, a := range attendues {
		if subtle.ConstantTimeCompare([]byte(a), []byte(presente)) == 1 {
			return false, "" // Conforme.
		}
	}

	return true, fmt.Sprintf(
		"la clé du core présente sur cette machine ne correspond à AUCUNE empreinte attestée.\n"+
			"  fichier              : %s\n"+
			"  empreinte du fichier : %s\n"+
			"  empreintes connues   : %s\n"+
			"\n"+
			"  Cette clé ne peut pas servir : le core ne saura pas déchiffrer ce qu'elle\n"+
			"  chiffre, et la connexion échouerait sur un « EOF » qui ne dirait pas pourquoi.\n"+
			"\n"+
			"  Elle est donc écartée et redemandée au core. La clé reçue sera comparée à\n"+
			"  l'empreinte ci-dessus : si le core a légitimement changé de clé, le service\n"+
			"  repart ; si quelque chose répond à sa place, la nouvelle clé sera refusée.\n"+
			"\n"+
			"  Si le refus persiste, comparez l'empreinte attendue à celle du core avec\n"+
			"  « vlt certificate fingerprint ». Si elles diffèrent, c'est l'empreinte de\n"+
			"  cette machine qui est périmée — réinstallez l'agent avec « vlt create -join ».",
		cheminCle, presente, attendue)
}

// EcarterCleLocale supprime la clé du core non conforme.
//
// Séparée de la vérification : constater et agir sont deux choses, et l'appelant
// doit pouvoir journaliser le motif avant que le fichier ne disparaisse.
func EcarterCleLocale() error {
	chemin := storage.CheminDansKeyPath("serveurpublickey.pem")
	if err := os.Remove(chemin); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("suppression de %s : %w", chemin, err)
	}
	return nil
}

// EcrireEmpreinte dépose l'empreinte sur la machine.
//
// Utilisé par l'installation. 0644 : l'empreinte n'est pas un secret, et sa
// lecture par un administrateur non root doit rester possible pour le
// diagnostic. C'est l'écriture qui doit être réservée, et le répertoire s'en
// charge.
func EcrireEmpreinte(empreinte string) error {
	if !strings.HasPrefix(empreinte, "SHA256:") {
		return fmt.Errorf("empreinte %q : forme attendue « SHA256:... »", empreinte)
	}
	if err := os.MkdirAll(storage.KeyPathResolu(), 0o700); err != nil {
		return err
	}
	contenu := "# Empreinte de la clé publique du core, déposée à l'installation.\n" +
		"# L'agent refuse toute clé qui ne correspond pas. Voir coretrust.go.\n" +
		empreinte + "\n"
	return os.WriteFile(CoreFingerprintPath(), []byte(contenu), 0o644)
}
