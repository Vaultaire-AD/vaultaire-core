package dbgpo

// legacyTablesToDrop liste les tables de l'ancien modèle GPO (une commande shell
// par distribution) supprimées lors du passage au modèle déclaratif. Elles sont
// retirées dans l'ordre des dépendances : la table de liaison d'abord.
var legacyTablesToDrop = []string{
	"group_linux_gpo",
	"linux_gpo_distributions",
}
