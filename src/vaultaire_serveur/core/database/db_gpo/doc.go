// Package dbgpo est la couche de persistance dédiée aux GPO Vaultaire.
//
// Elle est volontairement séparée du package database : les GPO ont leur propre
// schéma (une GPO, N modules, M groupes) et leur propre invariant de sécurité
// (aucun module ne doit entrer en base sans avoir été validé par le catalogue
// core/gpo). Isoler ce code évite que du CRUD générique contourne cette
// validation par inadvertance.
//
// Modèle relationnel :
//
//	gpo         — métadonnées d'une GPO (nom, scope, version, activation)
//	gpo_module  — une ligne par module, paramètres en JSON
//	gpo_group   — liaison N-N vers les groupes (une GPO ne s'applique qu'à des groupes)
//
// # Liaison GPO ↔ groupes
//
// Une GPO ne se rattache qu'à des groupes — jamais directement à un utilisateur
// ni à une machine. C'est ce qui permet de garder un seul point de vérité pour
// les droits (le groupe porte déjà les permissions, le domaine et les membres)
// et de rester cohérent avec le modèle de permissions RBAC du projet.
// Une GPO peut être liée à plusieurs groupes, et un groupe porter plusieurs GPO.
//
// # Persistance des restrictions
//
// Les listes d'autorisation, les règles de champ, les règles de chemin et les
// variables d'environnement interdites vivent en base et sont éditables par les
// membres du groupe superadmin `vaultaire` — et par eux seuls.
//
// La vérification d'appartenance est faite ICI, dans la couche base, et non
// seulement dans le handler web : c'est la seule façon de garantir qu'aucun
// appelant présent ou futur (CLI, API, LDAP) ne contourne la porte. Chaque
// écriture est journalisée en SECURITY avec son auteur, parce que modifier une
// restriction change ce que l'ensemble du parc accepte d'appliquer.
//
// Les fichiers de restriction se lisent en quatre familles, que leurs noms
// distinguent : peuplement et réinitialisation (setup_restrictions,
// reset_restrictions_to_defaults), lecture pour core/gpo (load_restrictions,
// list_*, get_field_rule), écriture réservée au superadmin (save_definition,
// add_*, set_*, delete_*), et utilitaires. Ces familles étaient auparavant des
// bandeaux de section dans un fichier de 830 lignes.
//
// # Peuplement initial
//
// Deux garanties tiennent le peuplement :
//
//  1. Les valeurs ne vivent nulle part dans le code Go. Elles sont dans
//     seed/gpo_seed.sql, embarqué dans le binaire. Le code Go ne connaît que la
//     structure des champs (core/gpo/dynamicfields.go), jamais leur contenu.
//
//  2. Une instruction de peuplement n'est exécutée que si sa table cible vient
//     d'être créée. C'est le point crucial : une valeur supprimée depuis
//     l'interface web ne peut pas réapparaître au redémarrage, puisque sa table
//     existait déjà et qu'aucune instruction ne la vise. Un marqueur en base
//     n'aurait pas suffi — il est lui-même supprimable.
//
// Cette granularité par table permet aussi de rattraper une base créée par une
// version antérieure : si gpo_value_definition est la seule table manquante,
// seules les définitions sont écrites, sans toucher aux listes existantes.
package dbgpo
