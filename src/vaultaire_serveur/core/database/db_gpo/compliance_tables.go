package dbgpo

// Schéma du suivi de conformité.
//
// # Ce que ces tables répondent
//
// Le rapport d'application (05_12) n'était que journalisé : le serveur savait ce
// qu'il avait DEMANDÉ, jamais ce qui avait été réellement appliqué. L'interface
// présentait donc la configuration voulue comme si c'était la configuration
// réelle — une machine en échec depuis trois semaines s'affichait exactement
// comme une machine à jour.
//
// # Trois tables et pas une
//
// gpo_compliance      : l'état COURANT d'une machine, une ligne par scope.
//
//	C'est la vue qu'on interroge en permanence.
//
// gpo_module_report   : le détail par module du DERNIER rapport. Sans lui, on
//
//	sait qu'une machine est en « partial » sans savoir quel
//	module a échoué, ce qui ne permet pas d'agir.
//
// gpo_drift           : les écarts constatés par le scan de conformité (05_15).
//
//	Séparés du rapport d'application parce qu'ils répondent
//	à une autre question : non pas « l'application a-t-elle
//	réussi » mais « est-ce encore vrai aujourd'hui ».
//
// Les trois sont ÉCRASÉES à chaque rapport, pas accumulées. Un historique
// complet des applications sur un parc de mille machines qui rapportent toutes
// les heures ferait des millions de lignes pour une question — « où en est-on
// maintenant ? » — à laquelle la dernière ligne suffit. La trace historique,
// c'est le journal.
var complianceTablesDDL = []string{
	`CREATE TABLE IF NOT EXISTS gpo_compliance (
		id_compliance   INT AUTO_INCREMENT PRIMARY KEY,
		computeur_id    VARCHAR(255) NOT NULL,
		scope           VARCHAR(16)  NOT NULL,
		target_user     VARCHAR(255) NOT NULL DEFAULT '',
		policy_version  INT          NOT NULL DEFAULT 0,
		fingerprint     VARCHAR(128) NOT NULL DEFAULT '',
		status          VARCHAR(16)  NOT NULL DEFAULT '',
		modules_total   INT          NOT NULL DEFAULT 0,
		modules_failed  INT          NOT NULL DEFAULT 0,
		modules_skipped INT          NOT NULL DEFAULT 0,
		reported_at     DATETIME     NOT NULL,
		drift_count     INT          NOT NULL DEFAULT 0,
		drift_checked   INT          NOT NULL DEFAULT 0,
		drift_at        DATETIME     NULL,
		-- Un scope par machine, et un par utilisateur sur cette machine.
		-- La contrainte porte les trois colonnes : sans target_user, deux
		-- utilisateurs de la même machine s'écraseraient l'un l'autre.
		UNIQUE KEY uniq_compliance (computeur_id, scope, target_user)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS gpo_module_report (
		id_module_report INT AUTO_INCREMENT PRIMARY KEY,
		computeur_id     VARCHAR(255) NOT NULL,
		scope            VARCHAR(16)  NOT NULL,
		target_user      VARCHAR(255) NOT NULL DEFAULT '',
		module_type      VARCHAR(64)  NOT NULL,
		state_key        VARCHAR(255) NOT NULL,
		result           VARCHAR(16)  NOT NULL,
		detail           TEXT         NULL,
		reported_at      DATETIME     NOT NULL,
		KEY idx_module_report (computeur_id, scope, target_user),
		-- Indexé sur le résultat : la requête la plus utile est « montre-moi
		-- tout ce qui a échoué dans le parc », et elle balaierait sinon la
		-- table entière.
		KEY idx_module_result (result)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS gpo_drift (
		id_drift     INT AUTO_INCREMENT PRIMARY KEY,
		computeur_id VARCHAR(255) NOT NULL,
		scope        VARCHAR(16)  NOT NULL,
		target_user  VARCHAR(255) NOT NULL DEFAULT '',
		state_key    VARCHAR(255) NOT NULL DEFAULT '',
		kind         VARCHAR(24)  NOT NULL,
		path         VARCHAR(1024) NOT NULL,
		detail       TEXT         NULL,
		detected_at  DATETIME     NOT NULL,
		KEY idx_drift (computeur_id, scope, target_user)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
}
