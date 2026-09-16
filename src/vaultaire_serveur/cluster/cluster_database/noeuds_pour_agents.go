package clusterdatabase

import (
	"database/sql"
	"fmt"
	"sort"

	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/core/logs"
)

// La liste des nœuds joignables, telle qu'un agent la reçoit.
//
// # Pourquoi le tri est fait par le SERVEUR
//
// Un agent ne voit qu'une adresse à la fois. Le serveur voit le parc entier :
// qui est en ligne, qui est chargé, qui vient de redémarrer.
//
// Trier côté agent supposerait de lui envoyer de quoi décider — métriques,
// affinités, état de chaque nœud — c'est-à-dire de distribuer à toutes les
// machines du parc une carte de l'infrastructure. Et chaque agent la trierait
// avec SA version du code : changer la règle demanderait de mettre à jour le
// parc avant qu'elle prenne effet.
//
// Le serveur rend donc une liste ORDONNÉE. L'agent la parcourt de haut en bas,
// sans rien décider.

// NoeudsPourAgents rend les nœuds qu'un agent peut joindre, dans l'ordre.
//
// # Ce qui est écarté, et pourquoi
//
// Un nœud sans PORT est omis : il a été enregistré par une version antérieure et
// n'a jamais déclaré sur quoi il écoute. L'annoncer donnerait une adresse que
// l'agent composerait avec un port deviné — donc une tentative qui échoue, un
// délai d'attente, et un basculement retardé d'autant.
//
// « Sans port » veut dire sans port DÉCLARÉ NI par le nœud ni par un
// administrateur. Un port public suffit donc à rendre joignable un nœud
// enregistré par une version antérieure : c'est même la seule façon de le
// remettre dans la liste sans attendre qu'il se réenregistre.
//
// L'ADRESSE et le PORT servis sont ceux d'AdresseEffective et PortEffectif : la
// déclaration de l'administrateur l'emporte sur ce que le nœud voit de lui-même.
// Un nœud derrière une redirection annonce une adresse privée que personne dans
// le parc ne peut joindre, et il n'a aucun moyen de s'en rendre compte.
//
// Un nœud sans EMPREINTE est omis, et c'est le filtre le plus important. Un
// agent qui apprend une adresse sans l'empreinte qui va avec devrait accepter la
// clé de ce nœud en aveugle à sa première connexion — c'est-à-dire faire
// exactement ce que le fichier d'empreintes existe pour empêcher. Mieux vaut ne
// pas annoncer un nœud que l'annoncer sans de quoi le reconnaître.
//
// Un nœud non exposé est omis aussi. Ce n'est PAS un contrôle d'accès : le
// drapeau retire une adresse d'une liste, il n'empêche personne de se
// connecter. Le pare-feu reste ce qui protège un core.
//
// # groupesDuDemandeur
//
// Les identifiants de groupes de l'agent qui demande. Ils ne FILTRENT rien : ils
// décident du rang. Un nœud affin passe devant les autres de son rôle, et les
// autres restent dans la liste — c'est ce qui fait qu'un site dont le proxy est
// tombé se rabat sur un core au lieu de n'avoir plus personne à joindre.
//
// Une liste vide — agent sans groupe, ou appelant qui ne sait pas qui demande —
// rend l'ordre d'avant le lot 6 : rôle, puis priorité, puis nom.
func NoeudsPourAgents(db *sql.DB, groupesDuDemandeur []int) ([]clusterstorage.Node, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}

	// Les affinités sont lues en UNE requête, avant la boucle.
	//
	// Une par nœud ferait, sur un cluster de dix nœuds, dix requêtes à chaque
	// démarrage d'agent et à chaque reconnexion de tunnel — pour une table qui
	// tient entièrement en mémoire.
	//
	// L'échec n'est PAS bloquant : mieux vaut servir la liste dans l'ordre
	// d'avant le lot 6 que ne rien servir. Sans nœud à joindre, un agent ne
	// s'authentifie plus ; mal trié, il s'authentifie par un chemin plus long.
	var affinites map[int][]int
	if len(groupesDuDemandeur) > 0 {
		var errAff error
		affinites, errAff = AffinitesParNoeud(db)
		if errAff != nil {
			logs.Write_Log("WARNING",
				"cluster: affinités illisibles, liste servie sans préférence de site : "+errAff.Error())
			affinites = nil
		}
	}

	rows, err := db.Query(`
		SELECT id_node, hostname, fqdn, ip_address, role, status, version_code,
		       capabilities, last_heartbeat, ducky_port, priorite, expose_aux_agents,
		       key_fingerprint, sdk_version, adresse_publique, port_public
		  FROM cluster_nodes
		 WHERE status = 'online'
		   AND expose_aux_agents = TRUE
		   AND (ducky_port > 0 OR port_public > 0)
		   AND key_fingerprint <> ''
		   AND role IN ('core', 'proxy')`)
	if err != nil {
		return nil, fmt.Errorf("lecture des nœuds joignables : %w", err)
	}
	defer func() { _ = rows.Close() }()

	var noeuds []clusterstorage.Node
	for rows.Next() {
		var n clusterstorage.Node
		if err := rows.Scan(&n.ID, &n.Hostname, &n.FQDN, &n.IPAddress, &n.Role, &n.Status,
			&n.VersionCode, &n.Capabilities, &n.LastHeartbeat, &n.Port, &n.Priorite,
			&n.ExposeAuxAgents, &n.Empreinte, &n.VersionSDK,
			&n.AdressePublique, &n.PortPublic); err != nil {
			return nil, fmt.Errorf("lecture d'un nœud : %w", err)
		}
		n.Affin = partageUnGroupe(affinites[n.ID], groupesDuDemandeur)
		noeuds = append(noeuds, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("parcours des nœuds : %w", err)
	}

	TrierNoeudsPourAgents(noeuds)
	return noeuds, nil
}

// partageUnGroupe dit si les deux ensembles se croisent.
//
// Deux boucles imbriquées, et non une map : ces listes comptent quelques
// entrées — les groupes d'un nœud et ceux d'une machine —, et construire une map
// par nœud coûterait plus que le parcours qu'elle éviterait.
func partageUnGroupe(a, b []int) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// TrierNoeudsPourAgents ordonne la liste servie à un agent.
//
// # L'ordre, et ce qu'il coûte
//
//	1. les PROXIES avant les cores ;
//	2. à rôle égal, les nœuds AFFINS d'abord ;
//	3. à affinité égale, la priorité la plus BASSE d'abord ;
//	4. à priorité égale, le nom — pour que l'ordre soit reproductible.
//
// # L'affinité vient APRÈS le rôle, et avant la priorité
//
// Après le rôle : un core affin ne doit pas passer devant un proxy quelconque.
// Le rôle décide de la NATURE du chemin — passer par un relais ou aller au
// serveur — et l'affinité seulement du choix entre pairs. L'ordre servi est donc
// bien celui de la spécification : proxies affins, autres proxies, cores affins,
// autres cores.
//
// Avant la priorité : la priorité est un réglage GLOBAL, l'affinité est locale
// au demandeur. Si la priorité l'emportait, un proxy mis en tête pour un site
// passerait devant le proxy local de tous les autres sites — c'est-à-dire que
// régler un site déréglerait les autres, ce qui est exactement ce que
// l'affinité existe pour éviter.
//
// L'affinité reste une PRÉFÉRENCE. Tous les nœuds exposés restent dans la
// liste, en queue : la panne du proxy d'un site ne doit pas devenir une panne
// d'authentification pour ce site.
//
// Les proxies d'abord : c'est leur raison d'être. Un parc qui en déploie veut
// que les agents y passent, sinon ils ne servent à rien. Les cores restent
// TOUJOURS dans la liste, en queue — un client dont tous les proxies échouent
// doit pouvoir joindre un core, sans quoi la panne d'un relais devient une panne
// d'authentification.
//
// # Zéro se range APRÈS
//
// Une priorité nulle vaut « sans préférence ». Si elle se rangeait avant, donner
// une priorité à un seul nœud le reléguerait derrière tous les autres — l'exact
// inverse de l'intention. C'est le piège classique d'un défaut à zéro sur un
// champ d'ordre, et il se paie une fois en production.
//
// # Séparé de la lecture
//
// L'ordre est ce sur quoi tout le parc s'appuie. Une fonction qui interroge la
// base ne s'éprouve qu'avec une base ; celle-ci s'éprouve avec quatre nœuds
// écrits à la main.
func TrierNoeudsPourAgents(noeuds []clusterstorage.Node) {
	sort.SliceStable(noeuds, func(i, j int) bool {
		a, b := noeuds[i], noeuds[j]

		if (a.Role == "proxy") != (b.Role == "proxy") {
			return a.Role == "proxy"
		}

		// À rôle égal, l'affinité départage avant tout le reste.
		if a.Affin != b.Affin {
			return a.Affin
		}

		pa, pb := prioriteEffective(a.Priorite), prioriteEffective(b.Priorite)
		if pa != pb {
			return pa < pb
		}

		// Départage par nom. Sans lui, deux nœuds de même rôle et même priorité
		// s'ordonneraient selon le plan d'exécution : la liste changerait d'une
		// requête à l'autre, et tout le parc basculerait ensemble sur un nœud
		// que rien n'a désigné.
		return a.Hostname < b.Hostname
	})
}

// prioriteEffective range zéro après les valeurs explicites.
func prioriteEffective(p int) int {
	if p <= 0 {
		// Pas MaxInt : deux nœuds sans priorité doivent rester ÉGAUX entre eux,
		// pour que le départage par nom joue. Une valeur haute mais finie suffit,
		// et la borne du schéma (INT) la laisse comparable.
		return 1 << 30
	}
	return p
}
