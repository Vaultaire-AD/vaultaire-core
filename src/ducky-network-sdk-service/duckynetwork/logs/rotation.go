package logs

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Rotation des journaux, faite PAR LE PROGRAMME.
//
// # Pourquoi pas logrotate
//
// Parce qu'il faudrait l'installer, le configurer et le maintenir sur chaque
// machine du parc, et qu'un fichier de configuration système de plus est une
// chose de plus qui peut manquer, diverger ou être écrasée par un outil de
// gestion de configuration. Un agent installé sans son fichier logrotate
// remplit sa partition sans que rien ne le signale — et c'est justement le parc
// qui compte ici, pas la machine qu'on regarde.
//
// Un programme qui écrit un journal sait quand celui-ci doit tourner. Il n'a
// besoin de le demander à personne.
//
// # La politique, en dur
//
// Ce ne sont pas des réglages : ce sont des valeurs par défaut saines, exposées
// en variables pour qu'un programme les ajuste au démarrage — le proxy voit
// passer le trafic de plusieurs machines et écrit davantage qu'un poste.
//
// Aucun fichier de configuration, aucune clé en base, aucune variable
// d'environnement. Le jour où une machine a un besoin particulier, c'est une
// ligne dans son `main`, pas une couche de configuration pour tout le monde.
//
// # Deux implémentations, et c'est imposé
//
// Le core et le socle réseau sont des modules Go DISJOINTS : le core n'importe
// pas `duckynetworkclient`. La même politique existe donc dans
// `vaultaire_serveur/core/logs`. Un test de chaque côté fige les mêmes valeurs,
// sinon les deux dérivent en silence.

var (
	// ArchivesConservees est le nombre de fichiers gardés en plus du courant.
	//
	// 30 : un mois glissant. C'est la fenêtre pendant laquelle on peut encore
	// remonter un incident signalé tardivement — « ça a commencé il y a trois
	// semaines ».
	ArchivesConservees = 30

	// TailleMaxJournal déclenche une rotation avant la fin de la journée.
	//
	// Sans elle, un emballement — une boucle d'authentification qui échoue,
	// chaque tentative écrivant — remplit la partition bien avant minuit, et la
	// rotation quotidienne arrive trop tard.
	//
	// 20 Mo pour un poste. Le proxy pose la sienne dans son main : il voit
	// passer le trafic de plusieurs machines, et un seuil de poste le ferait
	// tourner plusieurs fois par jour en fonctionnement sain — les 30 archives
	// ne couvriraient alors plus un mois mais quelques jours, c'est-à-dire que
	// la protection contre l'emballement mangerait la rétention.
	TailleMaxJournal int64 = 20 << 20

	// CompresserArchives : les archives sont gzippées, sauf la plus récente.
	//
	// La plus récente reste en clair parce que c'est celle qu'on lit le
	// lendemain d'un incident, et devoir la décompresser pour un `grep` ajoute
	// un geste au pire moment.
	CompresserArchives = true
)

// maintenantJournal est indirect pour que les tests avancent le temps.
var maintenantJournal = time.Now

// suffixeArchive est le format de date des archives : « .2026-08-14 ».
const suffixeArchive = "2006-01-02"

// rotationSiNecessaire fait tourner le fichier avant d'y écrire.
//
// Appelée sous le verrou d'écriture, donc jamais deux fois en parallèle.
//
// # Deux déclencheurs, et le premier n'est pas une horloge
//
// Le JOUR est lu dans la date de dernière modification du fichier, pas dans un
// minuteur. Un programme arrêté trois jours reprend avec un fichier dont la
// dernière ligne date de trois jours : elle part en archive à SA date, et non à
// celle du redémarrage. Un minuteur, lui, ne tourne pas quand le programme ne
// tourne pas — et aurait mélangé les deux périodes dans un même fichier.
//
// La TAILLE est le second, pour l'emballement intra-journalier.
//
// # Un échec de rotation n'empêche jamais d'écrire
//
// Fail-open, délibérément. Perdre la ligne parce que l'archivage a échoué
// reviendrait à faire taire le journal au moment précis où quelque chose ne va
// pas sur la machine — disque plein, droits changés. On écrit, et le fichier
// grossit : c'est visible, contrairement au silence.
func rotationSiNecessaire(chemin string) {
	info, err := os.Stat(chemin)
	if err != nil {
		return // pas de fichier : rien à faire
	}
	if info.Size() == 0 {
		return
	}

	maintenant := maintenantJournal()
	jourFichier := info.ModTime().Format(suffixeArchive)
	jourCourant := maintenant.Format(suffixeArchive)

	trop := TailleMaxJournal > 0 && info.Size() >= TailleMaxJournal
	if jourFichier == jourCourant && !trop {
		return
	}

	if err := archiver(chemin, jourFichier); err != nil {
		fmt.Printf("rotation du journal %s impossible: %v\n", chemin, err)
		return
	}
	purgerArchives(chemin)
}

// archiver renomme le fichier courant vers une archive datée.
//
// Le nom porte le jour du CONTENU, pas celui de l'archivage. Un fichier dont la
// dernière ligne est du 14 s'appelle « .2026-08-14 », même s'il est archivé le
// 17 au redémarrage — sinon les dates du nom ne correspondraient pas aux dates
// des lignes, et chercher « la journée du 14 » deviendrait un exercice.
//
// Un suffixe numérique est ajouté quand la date est déjà prise, ce qui arrive
// dès qu'un emballement déclenche plusieurs rotations le même jour.
func archiver(chemin string, jour string) error {
	base := chemin + "." + jour
	cible := base

	for i := 1; ; i++ {
		_, errPlein := os.Stat(cible)
		_, errGz := os.Stat(cible + ".gz")
		if os.IsNotExist(errPlein) && os.IsNotExist(errGz) {
			break
		}
		if i > 1000 {
			// Garde-fou : sans elle, un défaut de permission qui rend tous les
			// noms « déjà pris » ferait boucler indéfiniment, dans le chemin
			// d'écriture d'un journal, sous verrou.
			return fmt.Errorf("plus de 1000 archives pour %s", base)
		}
		cible = fmt.Sprintf("%s-%d", base, i)
	}

	if err := os.Rename(chemin, cible); err != nil {
		return err
	}

	// La compression vient APRÈS le renommage, et son échec n'annule rien : la
	// rotation a eu lieu, l'archive existe, elle est simplement en clair.
	if CompresserArchives {
		if err := compresserPlusAnciennes(chemin); err != nil {
			fmt.Printf("compression des archives de %s impossible: %v\n", chemin, err)
		}
	}
	return nil
}

// compresserPlusAnciennes gzippe toutes les archives sauf la plus récente.
func compresserPlusAnciennes(chemin string) error {
	archives, err := listerArchives(chemin)
	if err != nil {
		return err
	}
	// listerArchives rend de la plus récente à la plus ancienne : on saute la
	// première, qui doit rester lisible sans outil.
	for _, a := range archives[min(1, len(archives)):] {
		if strings.HasSuffix(a, ".gz") {
			continue
		}
		if err := compresser(a); err != nil {
			return err
		}
	}
	return nil
}

// compresser gzippe un fichier et retire l'original.
//
// L'original n'est retiré qu'après une écriture ET une fermeture réussies du
// gzip : l'ordre inverse perdrait l'archive si le disque est plein, ce qui est
// précisément la situation où la rotation se déclenche.
func compresser(chemin string) error {
	source, err := os.Open(chemin)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	destination, err := os.OpenFile(chemin+".gz", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	gz := gzip.NewWriter(destination)
	_, errCopie := io.Copy(gz, source)
	errFermetureGz := gz.Close()
	errFermeture := destination.Close()

	if errCopie != nil || errFermetureGz != nil || errFermeture != nil {
		_ = os.Remove(chemin + ".gz")
		return fmt.Errorf("compression de %s : %v / %v / %v",
			chemin, errCopie, errFermetureGz, errFermeture)
	}
	return os.Remove(chemin)
}

// purgerArchives supprime les archives au-delà d'ArchivesConservees.
func purgerArchives(chemin string) {
	if ArchivesConservees <= 0 {
		return
	}
	archives, err := listerArchives(chemin)
	if err != nil {
		fmt.Printf("purge des archives de %s impossible: %v\n", chemin, err)
		return
	}
	for _, a := range archives[min(ArchivesConservees, len(archives)):] {
		if err := os.Remove(a); err != nil {
			fmt.Printf("suppression de %s impossible: %v\n", a, err)
		}
	}
}

// listerArchives rend les archives d'un journal, de la plus récente à la plus
// ancienne.
//
// # Le tri porte sur le NOM et non sur la date de modification
//
// Les noms portent la date au format « AAAA-MM-JJ », qui se trie
// alphabétiquement dans l'ordre chronologique. C'est ce qui rend le tri sûr :
// la date de modification d'une archive change quand on la COMPRESSE, ce qui
// ferait passer une vieille archive pour la plus récente et la sauverait de la
// purge à la place d'une autre.
func listerArchives(chemin string) ([]string, error) {
	dir := filepath.Dir(chemin)
	prefixe := filepath.Base(chemin) + "."

	entrees, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var archives []string
	for _, e := range entrees {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefixe) {
			continue
		}
		archives = append(archives, filepath.Join(dir, e.Name()))
	}

	// Décroissant : « .2026-08-14.gz » et « .2026-08-14 » se suivent, le « .gz »
	// après — sans importance, ils ne coexistent que le temps d'une compression.
	sort.Sort(sort.Reverse(sort.StringSlice(archives)))
	return archives, nil
}
