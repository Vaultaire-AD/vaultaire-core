package logs

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"vaultaire/serveur/storage"
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
	SeverityEmergency = iota // 0
	SeverityAlert            // 1
	SeverityCritical         // 2
	SeverityError            // 3
	SeverityWarning          // 4
	SeverityNotice           // 5
	SeverityInformational    // 6
	SeverityDebug            // 7
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

// LogBuffer stocke les logs en mémoire pour la web UI (limite de taille)
type LogBuffer struct {
	mu       sync.RWMutex
	entries  []LogEntry
	maxSize  int
	hostname string
}

var (
	globalBuffer *LogBuffer
	bufferOnce   sync.Once
)

// getBuffer retourne le buffer global (singleton)
func getBuffer() *LogBuffer {
	bufferOnce.Do(func() {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "localhost"
		}
		globalBuffer = &LogBuffer{
			entries:  make([]LogEntry, 0, 1000),
			maxSize:  10000, // Limite: 10000 entrées max
			hostname: hostname,
		}
	})
	return globalBuffer
}

// addEntry ajoute une entrée au buffer (thread-safe, avec limite)
func (b *LogBuffer) addEntry(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries = append(b.entries, entry)

	// Si on dépasse la limite, supprimer les plus anciennes entrées
	if len(b.entries) > b.maxSize {
		// Garder les maxSize dernières entrées
		keep := b.entries[len(b.entries)-b.maxSize:]
		b.entries = make([]LogEntry, len(keep), b.maxSize)
		copy(b.entries, keep)
	}
}

// GetEntries retourne les entrées filtrées (thread-safe)
func (b *LogBuffer) GetEntries(levelFilter string, codeFilter string, limit int) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var filtered []LogEntry
	count := 0

	// Parcourir depuis la fin (logs les plus récents en premier)
	for i := len(b.entries) - 1; i >= 0 && count < limit; i-- {
		entry := b.entries[i]

		// Filtrer par niveau
		if levelFilter != "" && entry.Level != levelFilter {
			continue
		}

		// Filtrer par code
		if codeFilter != "" && entry.Code != codeFilter {
			continue
		}

		filtered = append(filtered, entry)
		count++
	}

	// Inverser pour avoir les plus anciens en premier dans le résultat
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}

	return filtered
}

// GetEntriesCount retourne le nombre total d'entrées
func (b *LogBuffer) GetEntriesCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
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
	case "DEBUG":
		return SeverityDebug
	default:
		return SeverityInformational
	}
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
	return ts + " [" + lvl + "] " + message
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
}

// Write_Log writes a log to stdout and buffer (no error code, no metadata).
func Write_Log(level string, content string) {
	Write_LogCode(level, CodeNone, content)
}

// Write_LogCode writes a log with RFC 5424 severity and optional error code.
// DEBUG logs are emitted only when storage.Debug is true.
func Write_LogCode(level string, code string, content string) {
	if strings.ToUpper(level) == "DEBUG" && !storage.Debug {
		return
	}
	writeEntry(level, code, content, nil)
}

// Write_LogCodeMeta writes a log with optional request_id and user_id for critical paths (auth, API, transactions).
// Never pass passwords or tokens in content or meta.
func Write_LogCodeMeta(level string, code string, content string, meta *LogMeta) {
	if strings.ToUpper(level) == "DEBUG" && !storage.Debug {
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

// GetLogsForWebUI retourne les logs filtrés pour la web UI (JSON)
func GetLogsForWebUI(levelFilter string, codeFilter string, limit int) ([]LogEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100 // Limite par défaut
	}
	return getBuffer().GetEntries(levelFilter, codeFilter, limit), nil
}

// GetLogsStats retourne les statistiques du buffer
func GetLogsStats() map[string]interface{} {
	buf := getBuffer()
	count := buf.GetEntriesCount()
	return map[string]interface{}{
		"total_entries": count,
		"max_size":      buf.maxSize,
		"hostname":      buf.hostname,
	}
}

// ClearLogs vide le buffer (pour tests ou maintenance)
func ClearLogs() {
	buf := getBuffer()
	buf.mu.Lock()
	defer buf.mu.Unlock()
	buf.entries = make([]LogEntry, 0, 1000)
}
