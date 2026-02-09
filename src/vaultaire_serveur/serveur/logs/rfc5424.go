package logs

import (
	"vaultaire/serveur/storage"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// RFC 5424 Syslog Protocol
// Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

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

// LogEntry représente une entrée de log pour la web UI
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Priority  int       `json:"priority"`
	Severity  int       `json:"severity"`
	Level     string    `json:"level"`
	Code      string    `json:"code,omitempty"`
	Message   string    `json:"message"`
	Hostname  string    `json:"hostname"`
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

// levelToSeverity convertit un niveau de log en severity RFC 5424 (syslog)
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
	case "WARNING", "WARN":
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

// canonicalLevel retourne le nom canonique du niveau pour affichage (RFC 5424)
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
	case "WARNING", "WARN":
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

// formatHumanReadable formate un log pour lecture humaine (docker logs, terminal)
// Ex: 2026-02-09 20:53:54 [INFO   ] database: connected successfully
func formatHumanReadable(level string, message string) string {
	ts := time.Now().Format("2006-01-02 15:04:05")
	lvl := canonicalLevel(level)
	if len(lvl) < 8 {
		lvl = lvl + strings.Repeat(" ", 8-len(lvl))
	} else if len(lvl) > 8 {
		lvl = lvl[:8]
	}
	return fmt.Sprintf("%s [%s] %s", ts, lvl, message)
}

// Write_Log écrit un log sur stdout (format lisible) et l'ajoute au buffer pour la web UI
func Write_Log(level string, content string) {
	Write_LogCode(level, CodeNone, content)
}

// Write_LogCode écrit un log avec code d'erreur en RFC 5424.
// Un seul flag (storage.Debug) contrôle tous les logs DEBUG : si debug: false dans la config, aucun log DEBUG n'est émis.
func Write_LogCode(level string, code string, content string) {
	if strings.ToUpper(level) == "DEBUG" && !storage.Debug {
		return
	}

	content = strings.TrimRight(content, "\n")
	severity := levelToSeverity(level)

	// Stdout: format lisible pour humains (docker logs, terminal)
	fmt.Fprintln(os.Stdout, formatHumanReadable(level, content))

	// Ajouter au buffer pour la web UI (niveau canonique RFC 5424)
	entry := LogEntry{
		Timestamp: time.Now(),
		Priority:  Facility*8 + severity,
		Severity:  severity,
		Level:     canonicalLevel(level),
		Code:      code,
		Message:   content,
		Hostname:  getBuffer().hostname,
	}
	getBuffer().addEntry(entry)
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
