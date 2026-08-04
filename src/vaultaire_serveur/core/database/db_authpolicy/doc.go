// Package dbauthpolicy porte le stockage du second facteur (TOTP) et de la
// politique d'expiration des mots de passe.
//
// Les deux sujets vivent dans le même paquet parce qu'ils répondent à la même
// question — « cette authentification est-elle encore recevable ? » — et sont
// interrogés par les mêmes trois chemins : bind LDAP, login web, et Ducky, qui
// porte PAM. Les séparer obligerait chaque chemin à connaître deux paquets et à
// composer lui-même les deux réponses, ce qui est exactement le genre de
// composition qu'on finit par oublier sur le troisième appelant.
//
// CE PAQUET NE DÉCIDE RIEN. Il lit et écrit. La décision — expiré, en préavis,
// valide — appartient à core/auth/passwordpolicy, qui n'a pas d'accès direct à
// la base et reçoit ses données d'ici. C'est ce qui permet de tester la règle
// sans base de données.
package dbauthpolicy
