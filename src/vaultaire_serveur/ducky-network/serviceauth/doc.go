// Package serviceauth porte la catégorie de trames 08 : un SERVICE du cluster
// fait vérifier par le core un compte que ses propres utilisateurs lui
// présentent.
//
// # À qui elle sert
//
// À tout client de la famille service qui authentifie des personnes pour son
// propre usage : le dépôt Nexus aujourd'hui, un service d'API ou un portail
// demain. Rien ici n'est propre à Nexus. Ce qu'un type de service peut
// apprendre sur un compte — la liste de clés RBAC renvoyée en « rights: » — est
// déclaré dans son entrée du catalogue (clienttype.Definition.UserRights).
//
// # Pourquoi une catégorie à part
//
//	02_0x  authentifie le PROGRAMME qui se connecte ;
//	03_01  authentifie un compte pour ouvrir une session sur une MACHINE
//	       (clés SSH, is_admin, droit de connexion au poste) ;
//	08_0x  vérifie un compte pour le compte d'un SERVICE, qui n'a ni clés SSH à
//	       recevoir ni machine à laquelle rattacher le droit de connexion.
//
// La restriction par sous-trame reste ainsi précise : l'agent n'émet pas 08,
// un service n'émet pas 03_01.
//
// # Les trames
//
//	08_01  service → core   service_user_auth        identifiant, mot de passe, otp:, from:, ref:
//	08_02  core → service   service_user_auth_ok     ref:, user:, name:, groups:, rights:, ttl:
//	08_03  core → service   service_user_auth_failed ref:, code:, reason:
//	08_04  service → core   service_user_refresh     ref:, user:
//	08_05  core → service   service_user_refresh_ok  (même contenu que 08_02)
//	08_06  core → service   service_user_refresh_denied  ref:, code:, reason:
//	08_07 … 08_19           réservées
//
// Toutes les lignes de contenu, hors identifiant et mot de passe de 08_01, sont
// PRÉFIXÉES. Un champ ajouté plus tard ne décale rien, et un champ absent est
// simplement vide — même choix que la ligne « groups: » de 03_02.
//
// « ref: » est un identifiant choisi par le service et RENVOYÉ tel quel. Le
// protocole n'a pas d'identifiant de requête : sans lui, deux vérifications
// simultanées sur la même session ne sauraient pas à qui revient chaque
// réponse.
//
// # Second facteur
//
// C'est ce qui justifie la catégorie face au bind LDAP, qui ne sait pas le
// porter. Un compte dont le second facteur est actif reçoit « mfa_required »
// tant que 08_01 n'a pas de ligne « otp: », puis le code est vérifié et
// CONSOMMÉ (anti-rejeu), exactement comme sur le portail. Un compte à qui un
// groupe impose le second facteur sans qu'il l'ait encore posé reçoit
// « mfa_enroll_required » : l'enrôlement se fait sur le portail.
//
// Le détail — ordre des contrôles, codes d'erreur — est dans
// docs/Developement/how it work/ducky-network/08-authentification-service.md.
package serviceauth
