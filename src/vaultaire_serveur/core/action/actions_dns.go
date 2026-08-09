package action

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	dnsdatabase "vaultaire/core/dns/DNS_Database"
	"vaultaire/core/permission"
)

// Actions sur les zones et enregistrements DNS.
//
// # Pourquoi la portée est globale
//
// « write:dns » figure parmi les actions spéciales de core/permission, et non
// parmi les clés « catégorie:action:objet ». Une zone DNS n'est pas une entité
// de l'annuaire : elle ne porte pas de domaine au sens des délégations, et le
// service qu'elle configure répond à tout le réseau.
//
// # Le TTL par défaut, et pourquoi il change de sens ici
//
// L'ancienne version web faisait :
//
//	ttl, _ := strconv.Atoi(ttlStr)
//	if ttl <= 0 { ttl = 300 }
//
// L'erreur d'analyse était ignorée, et « abc » devenait donc 300 secondes en
// silence. Une faute de frappe sur le TTL passait pour un choix.
//
// Ici, une valeur absente prend le défaut — c'est un choix légitime — mais une
// valeur PRÉSENTE et illisible est refusée. La distinction est celle entre
// « je n'ai rien dit » et « j'ai dit quelque chose d'incompréhensible ».

// ttlParDefaut est appliqué quand aucun TTL n'est fourni.
//
// 300 secondes, valeur de l'ancienne version. Assez court pour qu'une
// correction se propage dans la demi-heure, assez long pour ne pas transformer
// chaque résolution en requête.
const ttlParDefaut = 300

// EnregistrerActionsDNS ajoute les actions DNS au registre.
func EnregistrerActionsDNS(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "dns.create_zone",
		CleRBAC:  "write:dns",
		Portee:   PorteeGlobale,
		Resume:   "crée une zone DNS",
		Executer: creerZoneDNS,
	})

	r.MustEnregistrer(Definition{
		Nom:      "dns.add_record",
		CleRBAC:  "write:dns",
		Portee:   PorteeGlobale,
		Resume:   "ajoute un enregistrement dans une zone",
		Executer: ajouterEnregistrementDNS,
	})

	r.MustEnregistrer(Definition{
		Nom:      "dns.delete_record",
		CleRBAC:  "write:dns",
		Portee:   PorteeGlobale,
		Resume:   "supprime un enregistrement d'une zone",
		Executer: supprimerEnregistrementDNS,
	})

	r.MustEnregistrer(Definition{
		Nom:      "dns.delete_zone",
		CleRBAC:  "write:dns",
		Portee:   PorteeGlobale,
		Resume:   "supprime une zone et tous ses enregistrements",
		Executer: supprimerZoneDNS,
	})

	r.MustEnregistrer(Definition{
		Nom:      "dns.delete_ptr",
		CleRBAC:  "write:dns",
		Portee:   PorteeGlobale,
		Resume:   "supprime l'enregistrement inverse d'une adresse",
		Executer: supprimerPTR,
	})
}

// supprimerZoneDNS retire une zone entière.
//
// # Le message dit l'ampleur
//
// L'ancienne version rendait « Zone supprimée avec succès ». Supprimer une zone
// emporte TOUS ses enregistrements : les machines qu'elle résolvait deviennent
// injoignables par leur nom, et il n'existe aucun retour en arrière — la zone se
// recrée, son contenu non.
//
// Une confirmation par ressaisie n'est pas imposée ici : la commande est déjà
// réservée au droit write:dns, et l'interface web pose la sienne. L'ajouter
// dans l'action la rendrait obligatoire pour les deux façades, y compris pour
// un script d'automatisation légitime.
func supprimerZoneDNS(_ Appelant, p Params) (Resultat, error) {
	zone := strings.ToLower(p.Get("zone"))
	if zone == "" {
		return Resultat{}, fmt.Errorf("nom de zone requis")
	}
	if err := nomDNSAcceptable(zone); err != nil {
		return Resultat{}, fmt.Errorf("nom de zone invalide : %w", err)
	}

	if err := dnsdatabase.DeleteZone(dnsdatabase.GetDatabase(), zone); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression de la zone %q : %w", zone, err)
	}
	return Resultat{
		Message: fmt.Sprintf(
			"Zone %s supprimée, avec tous ses enregistrements. Les noms qu'elle "+
				"résolvait ne le sont plus.", zone),
		Donnees: map[string]string{"zone": zone},
	}, nil
}

// supprimerPTR retire la résolution inverse d'une adresse.
func supprimerPTR(_ Appelant, p Params) (Resultat, error) {
	ip := strings.TrimSpace(p.Get("ip"))
	if ip == "" {
		return Resultat{}, fmt.Errorf("adresse IP requise")
	}
	// Contrôle de forme : DeletePTRRecordByIP accepte n'importe quelle chaîne
	// et ne supprime alors rien, ce qui serait rapporté comme un succès.
	if net.ParseIP(ip) == nil {
		return Resultat{}, fmt.Errorf("adresse IP %q invalide", ip)
	}

	if err := dnsdatabase.DeletePTRRecordByIP(dnsdatabase.GetDatabase(), ip); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression du PTR de %s : %w", ip, err)
	}
	return Resultat{
		Message: fmt.Sprintf("Enregistrement inverse de %s supprimé.", ip),
		Donnees: map[string]string{"ip": ip},
	}, nil
}

func creerZoneDNS(_ Appelant, p Params) (Resultat, error) {
	zone := strings.ToLower(p.Get("zone_name"))
	if zone == "" {
		return Resultat{}, fmt.Errorf("nom de zone requis")
	}
	if err := nomDNSAcceptable(zone); err != nil {
		return Resultat{}, fmt.Errorf("nom de zone invalide : %w", err)
	}

	if err := dnsdatabase.CreateZoneTable(dnsdatabase.GetDatabase(), zone); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la création de la zone %q : %w", zone, err)
	}
	return Resultat{
		Message: fmt.Sprintf("Zone %s créée.", zone),
		Donnees: map[string]string{"zone": zone},
	}, nil
}

func ajouterEnregistrementDNS(_ Appelant, p Params) (Resultat, error) {
	zone := strings.ToLower(p.Get("zone"))
	nom := strings.ToLower(p.Get("name"))
	typeEnr := strings.ToUpper(p.Get("record_type"))
	donnee := p.Get("data")

	if zone == "" || nom == "" || typeEnr == "" || donnee == "" {
		return Resultat{}, fmt.Errorf("zone, nom, type et données requis")
	}
	if err := nomDNSAcceptable(zone); err != nil {
		return Resultat{}, fmt.Errorf("zone invalide : %w", err)
	}

	ttl, err := ttlDepuis(p)
	if err != nil {
		return Resultat{}, err
	}

	// La priorité ne concerne que MX et SRV. Une valeur illisible ailleurs
	// n'est pas une raison de refuser l'enregistrement, mais sur un MX elle
	// change l'ordre des serveurs de messagerie — donc on la contrôle.
	priorite := 0
	if brut := p.Get("priority"); brut != "" {
		priorite, err = strconv.Atoi(brut)
		if err != nil {
			return Resultat{}, fmt.Errorf("priorité invalide : %q n'est pas un nombre entier", brut)
		}
		if priorite < 0 {
			return Resultat{}, fmt.Errorf("priorité invalide : %d est négatif", priorite)
		}
	}

	fqdn := nomPleinementQualifie(nom, zone)
	if err := dnsdatabase.AddDNSRecordSmart(
		dnsdatabase.GetDatabase(), fqdn, typeEnr, ttl, donnee, priorite); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de l'ajout de %s %s : %w", typeEnr, fqdn, err)
	}

	return Resultat{
		Message: fmt.Sprintf("Enregistrement %s %s ajouté (TTL %d s).", typeEnr, fqdn, ttl),
		Donnees: map[string]any{"zone": zone, "fqdn": fqdn, "type": typeEnr, "ttl": ttl},
	}, nil
}

func supprimerEnregistrementDNS(_ Appelant, p Params) (Resultat, error) {
	zone := strings.ToLower(p.Get("zone"))
	nom := strings.ToLower(p.Get("record_name"))
	typeEnr := strings.ToUpper(p.Get("record_type"))

	if zone == "" || nom == "" || typeEnr == "" {
		return Resultat{}, fmt.Errorf("zone, nom et type requis")
	}

	fqdn := nomPleinementQualifie(nom, zone)
	if err := dnsdatabase.DeleteDNSRecord(dnsdatabase.GetDatabase(), fqdn, typeEnr); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression de %s %s : %w", typeEnr, fqdn, err)
	}
	return Resultat{
		Message: fmt.Sprintf("Enregistrement %s %s supprimé.", typeEnr, fqdn),
		Donnees: map[string]string{"zone": zone, "fqdn": fqdn},
	}, nil
}

// nomPleinementQualifie assemble le nom et la zone.
//
// « @ » désigne la zone elle-même — c'est la convention des fichiers de zone
// (RFC 1035 §5.1). Sans ce cas particulier, l'enregistrement s'appellerait
// « @.exemple.fr », un nom que personne ne résoudra jamais.
func nomPleinementQualifie(nom, zone string) string {
	if nom == "@" {
		return zone
	}
	return nom + "." + zone
}

// ttlDepuis applique le défaut à l'absence, mais refuse l'illisible.
//
// L'ancienne version écrivait `ttl, _ := strconv.Atoi(ttlStr)` : l'erreur était
// jetée, « abc » valait 0, puis 0 devenait 300. Une faute de frappe passait donc
// pour un choix délibéré, et le TTL réel n'était jamais celui qu'on croyait
// avoir saisi.
func ttlDepuis(p Params) (int, error) {
	brut := p.Get("ttl")
	if brut == "" {
		return ttlParDefaut, nil
	}
	ttl, err := strconv.Atoi(brut)
	if err != nil {
		return 0, fmt.Errorf("TTL invalide : %q n'est pas un nombre entier", brut)
	}
	if ttl <= 0 {
		// 0 explicite vaut « prends le défaut », comportement de l'ancienne
		// version qu'on conserve. Le négatif, lui, n'a pas de sens.
		if ttl == 0 {
			return ttlParDefaut, nil
		}
		return 0, fmt.Errorf("TTL invalide : %d est négatif", ttl)
	}
	return ttl, nil
}

// nomDNSAcceptable écarte ce qui ne peut pas être un nom de zone.
//
// Contrôle volontairement minimal : la base et le serveur DNS valident ensuite.
// Ce qui est écarté ici est ce qui rendrait la suite incompréhensible — un nom
// contenant une barre oblique ou un saut de ligne n'échouera pas avec un
// message parlant plus bas dans la pile.
func nomDNSAcceptable(nom string) error {
	if len(nom) > 253 {
		// RFC 1035 §2.3.4 : 255 octets pour le nom encodé, soit 253 en
		// représentation textuelle.
		return fmt.Errorf("%d caractères, maximum 253", len(nom))
	}
	if strings.ContainsAny(nom, " /\\\n\r\t") {
		return fmt.Errorf("caractères interdits (espaces, barres, sauts de ligne)")
	}
	if strings.HasPrefix(nom, ".") || strings.HasSuffix(nom, "..") {
		return fmt.Errorf("point mal placé")
	}
	return nil
}

// verifierActionDNSConnue garde une trace du fait que « write:dns » doit rester
// une action reconnue par core/permission.
//
// Si elle disparaissait de specialActions, les clés RBAC la contenant
// deviendraient invalides et toutes les actions DNS seraient refusées — sans
// que rien dans ce fichier ne change. Le test associé le vérifie.
func verifierActionDNSConnue() bool {
	_, ok := permission.IsValidAction("write:dns")
	return ok
}
