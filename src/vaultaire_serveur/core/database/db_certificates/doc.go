// Package dbcertificates porte les certificats TLS servis par l'API et par
// LDAPS.
//
// Ils ne portent aucun domaine, donc aucune clé RBAC ne s'y applique
// proprement : leur suppression est réservée au groupe superadmin `vaultaire`,
// comme les restrictions GPO et pour la même raison — un réglage qui engage
// tout le parc n'appartient à aucun domaine.
package dbcertificates
