package guardprotected

import isprotected "vaultaire/core/database/is_protected"

// GuardProtectedPermissionContent refuse toute écriture sur le contenu de la
// permission d'amorçage.
//
// Les autres gardes couvraient la suppression, le renommage et le déliage. Il
// restait un chemin plus discret pour arriver au même résultat : vider la
// permission de l'intérieur. `update -pu vaultaire_all web_admin nil` ne
// supprime rien, ne renomme rien, ne délie rien — et verrouille pourtant tout
// le monde hors de l'interface d'administration. La même opération sur les clés
// RBAC neutralise le compte d'amorçage action par action.
//
// C'est exactement ce que l'en-tête de ce fichier dit vouloir empêcher : se
// retrouver sans aucun chemin d'accès garanti à l'annuaire. La garde est donc
// posée ici, dans la couche base, pour couvrir le CLI, l'interface web et tout
// appelant futur d'un seul coup.
//
// Conséquence assumée : `vaultaire_all` n'est plus modifiable du tout. C'est
// voulu — cette permission n'a qu'un état correct, « tout autorisé ». Une
// délégation se construit en créant d'autres permissions, pas en rognant
// celle-ci.
func GuardProtectedPermissionContent(permissionName, action string) error {
	if isprotected.IsProtectedUserPermission(permissionName) {
		return refuseProtected("permission", permissionName,
			"la modification de l'action "+action)
	}
	return nil
}
