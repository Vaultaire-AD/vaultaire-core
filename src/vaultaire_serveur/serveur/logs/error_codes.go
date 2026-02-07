package logs

// Codes d'erreur standard pour le suivi et l'audit (format VLT-XXX).
const (
	CodeNone = ""

	// Base de données (VLT-DBxxx)
	CodeDBUserNotFound   = "VLT-DB001"
	CodeDBQuery          = "VLT-DB002"
	CodeDBConnection     = "VLT-DB003"
	CodeDBSession        = "VLT-DB004"

	// Authentification / permission (VLT-AUTHxxx)
	CodeAuthFailed       = "VLT-AUTH001"
	CodeAuthPermission   = "VLT-AUTH002"

	// Web / admin (VLT-WEBxxx)
	CodeWebTemplate   = "VLT-WEB001"
	CodeWebSession    = "VLT-WEB002"
	CodeWebAdmin      = "VLT-WEB003"

	// Ducky / réseau (VLT-NETxxx)
	CodeNetConnection = "VLT-NET001"
	CodeNetMessage    = "VLT-NET002"
	CodeNetKey        = "VLT-NET003"

	// Fichier / config (VLT-FILExxx)
	CodeFileConfig = "VLT-FILE001"
	CodeFileSocket = "VLT-FILE002"

	// Générique
	CodeInternal = "VLT-ERR000"
)
