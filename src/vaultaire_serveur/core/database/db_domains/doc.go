// Package dbdomains porte les domaines et leur résolution.
//
// Un domaine n'est pas une entité en soi dans le schéma : il est porté par la
// table domain_group, donc attaché à un groupe. C'est ce qui explique que la
// résolution d'un domaine passe toujours par un groupe ou un utilisateur.
package dbdomains
