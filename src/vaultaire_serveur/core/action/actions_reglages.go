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

// EnregistrerActionsReglages ajoute DNS (lecture), enrôlement (lecture) et
// réglages serveur.
func EnregistrerActionsReglages(r *Registre) {
	// --- DNS, lecture ---

	r.MustEnregistrer(Definition{
		Nom:             "dns.list_zones",
		CleRBAC:         permission.ActionReadDNS,
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
		FiltreInutile: "une zone DNS n'appartient à aucun domaine de l'annuaire ; " +
			"il n'y a pas de périmètre selon lequel réduire la liste",
		Resume:   "liste les zones DNS",
		Executer: listerZonesDNS,
	})

	r.MustEnregistrer(Definition{
		Nom:             "dns.list_records",
		CleRBAC:         permission.ActionReadDNS,
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
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
		UnDomaineSuffit: true,
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
		Resume:   "active ou coupe le mode debug",
		Executer: reglerDebug,
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

func reglerDebug(a Appelant, p Params) (Resultat, error) {
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

	return Resultat{Message: fmt.Sprintf("Mode debug : %v.", actif)}, nil
}

func purgerSessionsExpirees(a Appelant, _ Params) (Resultat, error) {
	if err := dbsessions.CleanUpExpiredSessions(database.GetDatabase()); err != nil {
		return Resultat{}, fmt.Errorf("nettoyage des sessions expirées : %w", err)
	}
	logs.Write_Log("INFO", a.Username+" a purgé les sessions expirées")
	return Resultat{Message: "Sessions expirées nettoyées."}, nil
}
