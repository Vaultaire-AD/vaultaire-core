package logs

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// RFC 5424 Syslog Protocol
// Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
// Severity: 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Informational, 7=Debug

const (
	RFC5424Version = "1"
	AppName        = "vaultaire-server"
	Facility       = 16 // local0
)

// Severity levels (RFC 5424)
const (
	SeverityEmergency     = iota // 0
	SeverityAlert                // 1
	SeverityCritical             // 2
	SeverityError                // 3
	SeverityWarning              // 4
	SeverityNotice               // 5
	SeverityInformational        // 6
	SeverityDebug                // 7
)

// LogMeta holds optional contextual metadata (request ID, user ID) for structured logging.
// Use WithMeta or Write_LogCodeMeta for critical paths (auth, API, DB transactions).
type LogMeta struct {
	RequestID string
	UserID    string // numeric or opaque ID; never log passwords or tokens
}

// LogEntry represents a log entry for stdout/buffer and web UI (RFC 5424 + optional metadata).
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Priority  int       `json:"priority"`
	Severity  int       `json:"severity"`
	Level     string    `json:"level"`
	Code      string    `json:"code,omitempty"`
	Message   string    `json:"message"`
	Hostname  string    `json:"hostname"`
	RequestID string    `json:"request_id,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
}

// levelToSeverity converts log level to RFC 5424 severity (0-7).
// SECURITY is mapped to Warning (4) for permission/audit events.
func levelToSeverity(level string) int {
	switch strings.ToUpper(level) {
	case "EMERGENCY", "EMERG":
		return SeverityEmergency
	case "ALERT":
		return SeverityAlert
	case "CRITICAL", "CRIT":
		return SeverityCritical
	case "ERROR", "ERR":
		return SeverityError
	case "WARNING", "WARN", "SECURITY":
		return SeverityWarning
	case "NOTICE":
		return SeverityNotice
	case "INFO", "INFORMATIONAL":
		return SeverityInformational
	case "DEBUG", "TRACE":
		// TRACE n'a pas de sévérité à lui : la RFC 5424 s'arrête à 7. Il porte
		// celle du DEBUG, et se distingue par son nom de niveau — voir detail.go.
		return SeverityDebug
	default:
		return SeverityInformational
	}
}

// SeveriteDe rend la sévérité RFC 5424 d'un nom de niveau, et false s'il est
// inconnu.
//
// Pour les FILTRES, là où levelToSeverity sert l'ÉCRITURE : un niveau inconnu
// y retombe sur INFO, ce qui est juste pour ne perdre aucune ligne, et faux
// pour un filtre — « WARNIGN » ferait alors montrer tout ce qui est plus grave
// qu'INFO, sans dire que la saisie n'a pas été comprise.
func SeveriteDe(niveau string) (int, bool) {
	switch strings.ToUpper(strings.TrimSpace(niveau)) {
	case "EMERGENCY", "EMERG", "ALERT", "CRITICAL", "CRIT", "ERROR", "ERR",
		"WARNING", "WARN", "SECURITY", "NOTICE", "INFO", "INFORMATIONAL", "DEBUG", "TRACE":
		return levelToSeverity(niveau), true
	}
	return 0, false
}

// canonicalLevel returns RFC 5424 canonical level name for display.
func canonicalLevel(level string) string {
	switch strings.ToUpper(level) {
	case "EMERGENCY", "EMERG":
		return "EMERGENCY"
	case "ALERT":
		return "ALERT"
	case "CRITICAL", "CRIT":
		return "CRITICAL"
	case "ERROR", "ERR":
		return "ERROR"
	case "WARNING", "WARN", "SECURITY":
		return "WARNING"
	case "NOTICE":
		return "NOTICE"
	case "INFO", "INFORMATIONAL":
		return "INFO"
	case "DEBUG":
		return "DEBUG"
	case "TRACE":
		return "TRACE"
	default:
		return "INFO"
	}
}

// formatRFC5424 formate un log selon RFC 5424 (pour agrégateurs / parsing machine)
func formatRFC5424(severity int, code string, message string) string {
	priority := Facility*8 + severity
	timestamp := time.Now().Format(time.RFC3339)
	hostname := getBuffer().hostname

	var structuredData string
	if code != "" {
		codeEscaped := strings.ReplaceAll(code, `"`, `\"`)
		structuredData = fmt.Sprintf(`[code@12345 code="%s"]`, codeEscaped)
	} else {
		structuredData = "-"
	}

	return fmt.Sprintf("<%d>%s %s %s %s - - %s %s",
		priority, RFC5424Version, timestamp, hostname, AppName, structuredData, message)
}

// logFormatJSON is set from env VAULTAIRE_LOG_FORMAT=json for structured JSON stdout.
var logFormatJSON bool

func init() {
	logFormatJSON = strings.TrimSpace(strings.ToLower(os.Getenv("VAULTAIRE_LOG_FORMAT"))) == "json"
}

// formatHumanReadable formats a log line for human reading (docker logs, terminal).
func formatHumanReadable(level string, message string) string {
	ts := time.Now().Format("2006-01-02 15:04:05")
	lvl := canonicalLevel(level)
	if len(lvl) < 8 {
		lvl = lvl + strings.Repeat(" ", 8-len(lvl))
	} else if len(lvl) > 8 {
		lvl = lvl[:8]
	}
	return ts + " [" + lvl + "] " + SurUneSeuleEntree(message)
}

// SurUneSeuleEntree met un message en forme pour un affichage LIGNE À LIGNE :
// ses lignes de suite sont décalées d'une tabulation, et un retour chariot est
// écrit en clair.
//
// # Le défaut que cela ferme — relevé en traitant le TO-DO 145
//
// Un message de journal reprend souvent ce qu'un client a envoyé : le nom d'un
// compte tiré d'un DN de bind, par exemple. Un DN portant un retour à la ligne
// suivi d'une date et d'un niveau écrivait donc, sur la sortie du core, une
// ligne que rien ne distinguait d'une vraie :
//
//	2026-10-03 13:17:26 [WARNING ] ldap bind: tentative sur le compte révoqué x
//	2026-10-03 13:00:00 [INFO    ] ldap bind: success user=admin …
//
// La seconde est forgée — par un inconnu, sans authentification. Qui lit le
// journal après un incident y trouve une connexion qui n'a pas eu lieu.
//
// Une vraie ligne commence par une date, en première colonne. Décalée, une
// ligne de suite ne peut plus passer pour telle, et les messages légitimement
// sur plusieurs lignes — la pile d'une panique, le vidage d'une entrée —
// restent lisibles.
//
// Le format JSON n'est pas concerné : l'encodeur y échappe les retours à la
// ligne. La table du journal commun non plus : un message y est UNE ligne de
// base, quel que soit son contenu. C'est à l'AFFICHAGE qu'il faut le faire —
// ici, et dans `vlt logs`.
func SurUneSeuleEntree(message string) string {
	if !strings.ContainsAny(message, "\n\r") {
		return message
	}
	message = strings.ReplaceAll(message, "\r", `\r`)
	return strings.ReplaceAll(message, "\n", "\n\t")
}

// formatJSONLine emits one JSON object per line (structured logging); no extra allocation for message.
func formatJSONLine(entry LogEntry) []byte {
	// Build minimal struct for stdout (timestamp as RFC3339 string for parsers)
	type stdoutLine struct {
		Time      string `json:"@timestamp"`
		Level     string `json:"level"`
		Code      string `json:"code,omitempty"`
		Message   string `json:"message"`
		Hostname  string `json:"hostname"`
		RequestID string `json:"request_id,omitempty"`
		UserID    string `json:"user_id,omitempty"`
	}
	line := stdoutLine{
		Time:      entry.Timestamp.Format(time.RFC3339),
		Level:     entry.Level,
		Code:      entry.Code,
		Message:   entry.Message,
		Hostname:  entry.Hostname,
		RequestID: entry.RequestID,
		UserID:    entry.UserID,
	}
	b, _ := json.Marshal(line)
	return b
}

// writeEntry emits one log entry to stdout and buffer. Caller must have already skipped DEBUG when needed.
func writeEntry(level string, code string, content string, meta *LogMeta) {
	content = strings.TrimRight(content, "\n")
	severity := levelToSeverity(level)
	now := time.Now()
	entry := LogEntry{
		Timestamp: now,
		Priority:  Facility*8 + severity,
		Severity:  severity,
		Level:     canonicalLevel(level),
		Code:      code,
		Message:   content,
		Hostname:  getBuffer().hostname,
	}
	if meta != nil {
		entry.RequestID = meta.RequestID
		entry.UserID = meta.UserID
	}

	if logFormatJSON {
		os.Stdout.Write(formatJSONLine(entry))
		os.Stdout.Write([]byte{'\n'})
	} else {
		fmt.Fprintln(os.Stdout, formatHumanReadable(level, content))
	}
	getBuffer().addEntry(entry)
	transmettre(entry)
}

// Write_Log writes a log to stdout and buffer (no error code, no metadata).
//
// Elle n'appelle PAS Write_LogCode, et c'est voulu : le sous-système d'une
// ligne DEBUG ou TRACE est déduit du fichier de l'appelant, à une profondeur de
// pile fixe (voir detail.go). Passer par une sœur ajouterait un cadre, et la
// ligne serait rangée avec ce paquet au lieu de celui qui l'a écrite.
func Write_Log(level string, content string) {
	if !emissionPermise(level, 2) {
		return
	}
	writeEntry(level, CodeNone, content, nil)
}

// Write_LogCode writes a log with RFC 5424 severity and optional error code.
//
// Les lignes DEBUG et TRACE ne sortent que si le détail du sous-système qui les
// écrit le demande : le réglage `debug`, ou son réglage propre (detail.go).
func Write_LogCode(level string, code string, content string) {
	if !emissionPermise(level, 2) {
		return
	}
	writeEntry(level, code, content, nil)
}

// Write_LogCodeMeta writes a log with optional request_id and user_id for critical paths (auth, API, transactions).
// Never pass passwords or tokens in content or meta.
func Write_LogCodeMeta(level string, code string, content string, meta *LogMeta) {
	if !emissionPermise(level, 2) {
		return
	}
	writeEntry(level, code, content, meta)
}

// WithMeta returns a LogMeta for use with Write_LogCodeMeta. userID can be numeric string or empty.
func WithMeta(requestID, userID string) *LogMeta {
	if requestID == "" && userID == "" {
		return nil
	}
	return &LogMeta{RequestID: requestID, UserID: userID}
}

// UserMeta returns LogMeta with only UserID set (e.g. for auth success).
func UserMeta(userID int) *LogMeta {
	if userID <= 0 {
		return nil
	}
	return &LogMeta{UserID: strconv.Itoa(userID)}
}

// EntreesEnMemoire rend les entrées gardées en mémoire par CE core, la plus
// récente en premier.
//
// Ce n'est plus la source du portail : les journaux se lisent en base, tous
// cores confondus (voir core/database/db_journaux). La mémoire reste le REPLI
// quand la base ne répond pas — c'est-à-dire au moment précis où l'on a le
// plus besoin de lire un journal.
func EntreesEnMemoire() []LogEntry {
	return getBuffer().recentes()
}

// CapaciteMemoire est le nombre d'entrées gardées en mémoire.
func CapaciteMemoire() int {
	return getBuffer().maxSize
}

// NomDuCore rend le nom sous lequel ce core signe ses journaux.
//
// C'est `os.Hostname()`, le MÊME nom que celui sous lequel le core s'inscrit
// au cluster (cluster.StartManager) : une ligne de journal et une ligne de
// `vlt cluster` doivent désigner un core de la même façon, sans table de
// correspondance à tenir.
func NomDuCore() string {
	return getBuffer().hostname
}

// ClearLogs vide le buffer (pour tests ou maintenance)
func ClearLogs() {
	buf := getBuffer()
	buf.mu.Lock()
	defer buf.mu.Unlock()
	buf.entries = make([]LogEntry, 0, 1000)
}
