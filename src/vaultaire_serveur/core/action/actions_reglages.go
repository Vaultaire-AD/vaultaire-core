package action

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbenrollment "vaultaire/core/database/db_enrollment"
	dbsessions "vaultaire/core/database/db_sessions"
	dnsdatabase "vaultaire/core/dns/DNS_Database"
	dnsstorage "vaultaire/core/dns/DNS_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

// Lectures DNS, enrôlement, et réglages du serveur.
//
// Le dernier lot : les quatre surfaces qui décidaient encore de leurs droits
// hors du registre. Toutes empruntaient une clé qui disait autre chose que ce
// qu'elles font.
//
//	dns zone list         write:dns          un droit d'ÉCRITURE pour une lecture
//	enroll list / show    read:get:client    l'annuaire des postes pour voir des clés
//	clear                 write:update:user  le droit de modifier des comptes
//	update -debug         write:update:user  idem
//
// Les deux derniers sont les plus parlants : régler le mode debug ou vider une
// table de sessions n'a rien d'une modification de compte. La clé accordait
// beaucoup plus que ce que la commande fait, et son nom ne laissait pas deviner
// qu'elle ouvrait ces deux-là.

// # Ces droits sont des BOOLÉENS, et c'est délibéré
//
// read:dns, read:enrollment, write:server — comme read:cluster, write:cluster,
// read:certificate, write:certificate et read:log — ne se délèguent PAS par
// domaine. Ils portent sur des objets qui n'appartiennent à aucun domaine de
// l'annuaire : une zone DNS, une clé d'enrôlement, le mode debug du serveur.
//
// Ils gardent donc PorteeGlobale sans PorteeOuverte : on les accorde avec
// « all », ou pas du tout. Leur donner une liste de domaines ne les
// restreindrait pas, elle les REFUSERAIT — la portée exige « * », qu'aucune
// liste de domaines ne satisfait.
//
// Le `UnDomaineSuffit: true` qu'ils portaient a été retiré : il ne faisait rien.
// « au moins un des domaines de la liste » appliqué à `["*"]` n'a qu'un seul
// candidat, `*`. Le laisser laissait croire à une souplesse qui n'existait pas —
// et c'est exactement la confusion qui a rendu les listes d'entités
// inaccessibles aux délégués pendant tout un cycle.

// EnregistrerActionsReglages ajoute DNS (lecture), enrôlement (lecture) et
// réglages serveur.
func EnregistrerActionsReglages(r *Registre) {
	// --- DNS, lecture ---

	r.MustEnregistrer(Definition{
		Nom:     "dns.list_zones",
		CleRBAC: permission.ActionReadDNS,
		Portee:  PorteeGlobale,
		FiltreInutile: "une zone DNS n'appartient à aucun domaine de l'annuaire ; " +
			"il n'y a pas de périmètre selon lequel réduire la liste",
		Resume:   "liste les zones DNS",
		Executer: listerZonesDNS,
	})

	r.MustEnregistrer(Definition{
		Nom:     "dns.list_records",
		CleRBAC: permission.ActionReadDNS,
		Portee:  PorteeGlobale,
		FiltreInutile: "un enregistrement DNS n'appartient à aucun domaine de " +
			"l'annuaire ; il n'y a pas de périmètre selon lequel réduire la liste",
		Resume:   "liste les enregistrements d'une zone",
		Executer: listerEnregistrementsDNS,
	})

	// --- enrôlement, lecture ---

	r.MustEnregistrer(Definition{
		Nom:     "enroll.list_keys",
		CleRBAC: permission.ActionReadEnrollment,
		Portee:  PorteeGlobale,
		// Les clés RÉVOQUÉES, expirées et épuisées sont incluses : la question
		// « qui a émis une clé pour ce type, et quand ? » se pose surtout après
		// coup. Les masquer rendrait l'audit impossible.
		FiltreInutile: "une clé d'enrôlement n'appartient à aucun domaine ; il n'y " +
			"a pas de périmètre selon lequel réduire la liste",
		Resume:   "liste les clés d'enrôlement",
		Executer: listerClesEnrolement,
	})

	// --- réglages du serveur ---

	r.MustEnregistrer(Definition{
		Nom:      "server.set_debug",
		CleRBAC:  permission.ActionWriteServer,
		Portee:   PorteeGlobale,
		Resume:   "active ou coupe le mode debug, pour tout le serveur ou un sous-système",
		Executer: reglerDebug,
	})

	// La LECTURE du réglage (TO-DO 145).
	//
	// Elle n'existait pas en ligne de commande : le mode debug se posait par
	// `update -debug` et ne se relisait que sur le portail. Avec un réglage par
	// sous-système, « dans quel état est le journal ? » devient une vraie
	// question — et un réglage qu'on ne peut pas relire là où on l'a posé est
	// un réglage qu'on repose « au cas où ».
	//
	// `read:log`, la clé du journal : savoir ce que le journal contient relève
	// de qui a le droit de le lire. C'est aussi celle des autres lectures de
	// réglages du serveur (signature des GPO, second facteur Ducky).
	r.MustEnregistrer(Definition{
		Nom:     "server.get_debug",
		CleRBAC: permission.ActionReadLog,
		Portee:  PorteeGlobale,
		// Inerte sous PorteeGlobale, déclaré pour l'invariant : toute lecture
		// le déclare.
		UnDomaineSuffit: true,
		FiltreInutile: "le détail du journal est un réglage du serveur ; il " +
			"n'appartient à aucun domaine",
		Resume:   "affiche le détail du journal : mode debug et réglage par sous-système",
		Executer: lireDebug,
	})

	r.MustEnregistrer(Definition{
		Nom:      "server.clear_sessions",
		CleRBAC:  permission.ActionWriteServer,
		Portee:   PorteeGlobale,
		Resume:   "purge les sessions expirées",
		Executer: purgerSessionsExpirees,
	})
}

// --- DNS ---------------------------------------------------------------------

func listerZonesDNS(_ Appelant, _ Params) (Resultat, error) {
	zones, err := dnsdatabase.GetAllDNSZones(dnsdatabase.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des zones DNS : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d zone(s) DNS.", len(zones)),
		Donnees: zones,
	}, nil
}

// EnregistrementsDeZone porte les enregistrements avec le nom de leur zone.
//
// Les enregistrements seuls ne disent pas de quelle zone ils viennent, et
// l'affichage en a besoin pour son titre.
type EnregistrementsDeZone struct {
	Zone            string
	Enregistrements []dnsstorage.ZoneRecord
}

func listerEnregistrementsDNS(_ Appelant, p Params) (Resultat, error) {
	zone := strings.ToLower(strings.TrimSpace(p.Get("zone")))
	if zone == "" {
		return Resultat{}, fmt.Errorf("nom de zone requis")
	}
	records, err := dnsdatabase.GetZoneRecords(dnsdatabase.GetDatabase(), zone)
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture de la zone %q : %w", zone, err)
	}
	return Resultat{
		Message: fmt.Sprintf("Zone %s : %d enregistrement(s).", zone, len(records)),
		Donnees: EnregistrementsDeZone{Zone: zone, Enregistrements: records},
	}, nil
}

// --- enrôlement --------------------------------------------------------------

func listerClesEnrolement(_ Appelant, _ Params) (Resultat, error) {
	cles, err := dbenrollment.ListKeys(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des clés d'enrôlement : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d clé(s) d'enrôlement.", len(cles)),
		Donnees: cles,
	}, nil
}

// --- réglages ----------------------------------------------------------------

// EtatDuDebug est ce que rend `server.get_debug`.
type EtatDuDebug struct {
	// Debug : le réglage général, celui de `debug: true|false`.
	Debug bool `json:"debug"`
	// SousSystemes : un par sous-système réglable, dans l'ordre d'affichage.
	SousSystemes []DetailDeSousSysteme `json:"sous_systemes"`
}

// DetailDeSousSysteme décrit le détail d'un sous-système.
type DetailDeSousSysteme struct {
	Nom string `json:"nom"`
	// Regle : le réglage PROPRE, « off », « debug » ou « trace » ; vide quand
	// le sous-système suit le réglage général.
	Regle string `json:"regle"`
	// Effectif : ce que le sous-système écrit réellement.
	Effectif string `json:"effectif"`
}

// LireEtatDuDebug compose l'état, pour l'action et pour la page d'accueil de
// l'administration — qui l'affiche à tout administrateur web, comme elle
// affichait déjà le booléen.
func LireEtatDuDebug() EtatDuDebug {
	etat := EtatDuDebug{Debug: storage.Debug}
	for _, s := range logs.SousSystemes() {
		d := DetailDeSousSysteme{Nom: string(s), Effectif: logs.DetailDe(s).String()}
		if propre, regle := logs.DetailRegle(s); regle {
			d.Regle = propre.String()
		}
		etat.SousSystemes = append(etat.SousSystemes, d)
	}
	return etat
}

// Texte rend l'état sous la forme affichée en ligne de commande.
func (e EtatDuDebug) Texte() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Mode debug : %v.\n", e.Debug)
	b.WriteString("Détail par sous-système :\n")
	for _, s := range e.SousSystemes {
		regle := "suit le mode debug"
		if s.Regle != "" {
			regle = "réglé à " + s.Regle
		}
		fmt.Fprintf(&b, "  %-6s %-6s (%s)\n", s.Nom, s.Effectif, regle)
	}
	return strings.TrimRight(b.String(), "\n")
}

func lireDebug(_ Appelant, _ Params) (Resultat, error) {
	etat := LireEtatDuDebug()
	return Resultat{Message: etat.Texte(), Donnees: etat}, nil
}

// reglerDebug règle le détail du journal.
//
// Deux formes, une seule action — c'est le même réglage, gardé par le même
// droit :
//
//	debug=true|false                    tout le serveur, comme toujours
//	sous_systeme=ldap niveau=trace      un sous-système (TO-DO 145)
func reglerDebug(a Appelant, p Params) (Resultat, error) {
	if strings.TrimSpace(p.Get("sous_systeme")) != "" {
		return reglerDetail(a, p)
	}

	brut := strings.ToLower(strings.TrimSpace(p.Get("debug")))
	if brut == "" {
		return Resultat{}, fmt.Errorf("valeur requise : true ou false")
	}

	var actif bool
	switch brut {
	case "true", "1", "on", "oui", "yes":
		actif = true
	case "false", "0", "off", "non", "no":
		actif = false
	default:
		// Refus explicite plutôt que « tout ce qui n'est pas vrai est faux ».
		//
		// L'ancienne version avait un `default` qui refusait, mais seules six
		// formes étaient reconnues. Une faute de frappe — « ture » — coupait
		// donc le debug en annonçant une valeur invalide, ce qui laissait
		// croire que rien n'avait changé.
		return Resultat{}, fmt.Errorf(
			"valeur %q invalide : attendu true ou false", p.Get("debug"))
	}

	storage.Debug = actif

	// Journalisé en SECURITY : le mode debug change ce que les journaux
	// contiennent, donc ce qu'un audit pourra reconstituer plus tard.
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a réglé le mode debug à %v", a.Username, actif))

	etat := LireEtatDuDebug()
	return Resultat{Message: etat.Texte(), Donnees: etat}, nil
}

// reglerDetail règle le détail d'UN sous-système.
//
// Le réglage vit en mémoire, sur CE core, comme le mode debug : il sert à un
// diagnostic et ne survit pas à un redémarrage. Pour le rendre durable, la
// section `debug.detail` de serveur_conf.yaml.
func reglerDetail(a Appelant, p Params) (Resultat, error) {
	sous, connu := logs.SousSystemeNomme(p.Get("sous_systeme"))
	if !connu {
		return Resultat{}, fmt.Errorf("sous-système %q inconnu : attendu %s",
			p.Get("sous_systeme"), logs.NomsDesSousSystemes())
	}
	if strings.TrimSpace(p.Get("niveau")) == "" {
		return Resultat{}, fmt.Errorf("niveau requis : off, debug, trace ou defaut")
	}
	niveau, herite, err := logs.LireDetail(p.Get("niveau"))
	if err != nil {
		return Resultat{}, err
	}

	dit := niveau.String()
	if herite {
		logs.LaisserDetail(sous)
		dit = "defaut (suit le mode debug)"
	} else {
		logs.ReglerDetail(sous, niveau)
	}

	// SECURITY, comme le mode debug et pour la même raison : ce réglage change
	// ce que le journal contient. Le niveau trace, en particulier, y écrit le
	// contenu des entrées de l'annuaire.
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a réglé le détail du journal de %s à %s", a.Username, sous, dit))

	etat := LireEtatDuDebug()
	return Resultat{Message: etat.Texte(), Donnees: etat}, nil
}

func purgerSessionsExpirees(a Appelant, _ Params) (Resultat, error) {
	if err := dbsessions.CleanUpExpiredSessions(database.GetDatabase()); err != nil {
		return Resultat{}, fmt.Errorf("nettoyage des sessions expirées : %w", err)
	}
	logs.Write_Log("INFO", a.Username+" a purgé les sessions expirées")
	return Resultat{Message: "Sessions expirées nettoyées."}, nil
}
