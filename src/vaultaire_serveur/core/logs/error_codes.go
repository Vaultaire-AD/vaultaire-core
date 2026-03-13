package logs

// Codes d'erreur standard pour le suivi et l'audit (RFC 5424 structured-data, format VLT-XXX).
const (
	CodeNone = ""

	// Base de données (VLT-DBxxx)
	CodeDBGeneric       = "VLT-DB000"
	CodeDBUserNotFound  = "VLT-DB001"
	CodeDBQuery         = "VLT-DB002"
	CodeDBConnection    = "VLT-DB003"
	CodeDBSession       = "VLT-DB004"
	CodeDBCreateTable   = "VLT-DB005"

	// Certificats / clés (VLT-CERTxxx)
	CodeCertNotFound   = "VLT-CERT001"
	CodeCertSave       = "VLT-CERT002"
	CodeCertLoad       = "VLT-CERT003"

	// API (VLT-APIxxx)
	CodeAPIDecode   = "VLT-API001"
	CodeAPISign     = "VLT-API002"
	CodeAPITLS      = "VLT-API003"

	// LDAP (VLT-LDAPxxx)
	CodeLDAPListen = "VLT-LDAP001"
	CodeLDAPTLS    = "VLT-LDAP002"

	// Authentification / permission (VLT-AUTHxxx)
	CodeAuthFailed       = "VLT-AUTH001"
	CodeAuthPermission   = "VLT-AUTH002"
	CodeAuthLoginDenied  = "VLT-AUTH003" // permission denied / security event

	// Web / admin (VLT-WEBxxx)
	CodeWebTemplate = "VLT-WEB001"
	CodeWebSession  = "VLT-WEB002"
	CodeWebAdmin    = "VLT-WEB003"

	// Ducky / réseau (VLT-NETxxx)
	CodeNetConnection = "VLT-NET001"
	CodeNetMessage    = "VLT-NET002"
	CodeNetKey        = "VLT-NET003"
	CodeNetParse      = "VLT-NET004"
	CodeNetBuild      = "VLT-NET005"
	CodeNetSend       = "VLT-NET006"

	// Fichier / config (VLT-FILExxx)
	CodeFileConfig = "VLT-FILE001"
	CodeFileSocket = "VLT-FILE002"

	// Générique
	CodeInternal = "VLT-ERR000"
)
