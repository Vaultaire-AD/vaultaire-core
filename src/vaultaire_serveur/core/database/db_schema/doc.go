// Package dbschema crée la base et l'amorce.
//
// Appelé au démarrage du serveur. Tout y est idempotent : CREATE TABLE IF NOT
// EXISTS et INSERT IGNORE, pour que les bases existantes rattrapent les
// nouveautés sans script de migration, et qu'un réglage volontairement restreint
// par un administrateur ne soit pas rouvert dans son dos.
package dbschema
