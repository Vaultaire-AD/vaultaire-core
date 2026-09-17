// Package usage trace qui télécharge quoi, et en tire des statistiques.
//
// # Deux formes
//
//   - le JOURNAL : un fichier JSON Lines par jour dans <data_dir>/usage/,
//     l'historique brut, exportable, purgé au-delà de retention_days ;
//   - les COMPTEURS : en mémoire, reconstruits au démarrage depuis le journal,
//     pour que les pages et l'API répondent sans relire des fichiers.
//
// L'écriture passe par un canal : un téléchargement n'attend jamais le disque.
// Si le canal déborde (disque bloqué), l'évènement est compté comme perdu
// plutôt que de ralentir les clients — et la perte est visible.
package usage

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Actions tracées.
const (
	ActionDownload = "download"
	ActionUpload   = "upload"
	ActionDelete   = "delete"
	ActionPull     = "pull" // manifeste Docker lu
	ActionPush     = "push" // manifeste Docker écrit
	ActionIndex    = "index"
)

// Event est une ligne du journal.
type Event struct {
	Time     time.Time `json:"t"`
	Action   string    `json:"a"`
	Repo     string    `json:"r"`
	RepoType string    `json:"rt"`
	Name     string    `json:"n,omitempty"`
	Version  string    `json:"v,omitempty"`
	File     string    `json:"f,omitempty"`
	User     string    `json:"u"`
	IP       string    `json:"ip"`
	Agent    string    `json:"ua,omitempty"`
	Bytes    int64     `json:"b,omitempty"`
	Status   int       `json:"s"`
	Millis   int64     `json:"ms,omitempty"`
}

// Tracker est le suivi d'utilisation.
type Tracker struct {
	dir       string
	retention int
	anonymize bool
	log       *slog.Logger
	ch        chan Event
	dropped   atomic.Int64

	mu     sync.RWMutex
	stats  map[string]*Counter // clé : repo \x00 name
	recent []Event             // anneau des derniers évènements
	daily  map[string]*Day     // date -> totaux
	client map[string]*Client  // ip -> activité
}

// Counter compte l'usage d'un paquet ou d'une image.
type Counter struct {
	Repo      string           `json:"repo"`
	Name      string           `json:"name"`
	Downloads int64            `json:"downloads"`
	Bytes     int64            `json:"bytes"`
	Users     map[string]bool  `json:"users"`
	Last      time.Time        `json:"last"`
	ByVersion map[string]int64 `json:"by_version"`
}

// Day est un total journalier.
type Day struct {
	Date      string `json:"date"`
	Downloads int64  `json:"downloads"`
	Uploads   int64  `json:"uploads"`
	Bytes     int64  `json:"bytes"`
	Denied    int64  `json:"denied"`
}

// Client est l'activité d'une adresse.
type Client struct {
	IP        string
	Users     map[string]bool
	Agent     string
	Downloads int64
	Bytes     int64
	Last      time.Time
}

const recentSize = 500

// Open démarre le suivi et relit l'historique.
func Open(dataDir string, retentionDays int, anonymize bool, log *slog.Logger) (*Tracker, error) {
	t := &Tracker{
		dir: filepath.Join(dataDir, "usage"), retention: retentionDays, anonymize: anonymize, log: log,
		ch:    make(chan Event, 4096),
		stats: map[string]*Counter{}, daily: map[string]*Day{}, client: map[string]*Client{},
	}
	if err := os.MkdirAll(t.dir, 0o750); err != nil {
		return nil, err
	}
	t.purge()
	t.reload()
	return t, nil
}

// Record enregistre un évènement sans bloquer.
func (t *Tracker) Record(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if t.anonymize {
		e.IP = anonymize(e.IP)
	}
	if len(e.Agent) > 200 {
		e.Agent = e.Agent[:200]
	}
	t.apply(e)
	select {
	case t.ch <- e:
	default:
		t.dropped.Add(1)
	}
}

// Dropped rend le nombre d'évènements non écrits.
func (t *Tracker) Dropped() int64 { return t.dropped.Load() }

// Run écrit le journal jusqu'à l'annulation du contexte.
func (t *Tracker) Run(ctx context.Context) {
	var f *os.File
	var w *bufio.Writer
	day := ""
	flush := time.NewTicker(2 * time.Second)
	purge := time.NewTicker(6 * time.Hour)
	defer flush.Stop()
	defer purge.Stop()
	closeFile := func() {
		if f != nil {
			w.Flush()
			f.Close()
			f = nil
		}
	}
	defer closeFile()
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case e := <-t.ch:
					t.write(&f, &w, &day, e)
				default:
					return
				}
			}
		case e := <-t.ch:
			t.write(&f, &w, &day, e)
		case <-flush.C:
			if w != nil {
				w.Flush()
			}
		case <-purge.C:
			t.purge()
		}
	}
}

func (t *Tracker) write(f **os.File, w **bufio.Writer, day *string, e Event) {
	d := e.Time.UTC().Format("2006-01-02")
	if d != *day || *f == nil {
		if *f != nil {
			(*w).Flush()
			(*f).Close()
		}
		nf, err := os.OpenFile(filepath.Join(t.dir, d+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			t.log.Error("usage: ouverture du journal", "err", err)
			*f = nil
			return
		}
		*f, *w, *day = nf, bufio.NewWriter(nf), d
	}
	b, _ := json.Marshal(e)
	(*w).Write(b)
	(*w).WriteByte('\n')
}

func (t *Tracker) purge() {
	cut := time.Now().UTC().AddDate(0, 0, -t.retention).Format("2006-01-02")
	entries, _ := os.ReadDir(t.dir)
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".jsonl")
		if name != e.Name() && name < cut {
			os.Remove(filepath.Join(t.dir, e.Name()))
		}
	}
}

func (t *Tracker) reload() {
	entries, _ := os.ReadDir(t.dir)
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, name := range files {
		f, err := os.Open(filepath.Join(t.dir, name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			var e Event
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				t.apply(e)
			}
		}
		f.Close()
	}
}

func success(status int) bool { return status >= 200 && status < 400 }

func (t *Tracker) apply(e Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recent = append(t.recent, e)
	if len(t.recent) > recentSize {
		t.recent = t.recent[len(t.recent)-recentSize:]
	}
	d := e.Time.UTC().Format("2006-01-02")
	day, ok := t.daily[d]
	if !ok {
		day = &Day{Date: d}
		t.daily[d] = day
	}
	if e.Status == 401 || e.Status == 403 {
		day.Denied++
	}
	if !success(e.Status) {
		return
	}
	switch e.Action {
	case ActionUpload, ActionPush:
		day.Uploads++
		return
	case ActionDownload, ActionPull:
	default:
		return
	}
	day.Downloads++
	day.Bytes += e.Bytes

	if e.Name != "" {
		k := e.Repo + "\x00" + e.Name
		c, ok := t.stats[k]
		if !ok {
			c = &Counter{Repo: e.Repo, Name: e.Name, Users: map[string]bool{}, ByVersion: map[string]int64{}}
			t.stats[k] = c
		}
		c.Downloads++
		c.Bytes += e.Bytes
		c.Users[e.User] = true
		if e.Version != "" {
			c.ByVersion[e.Version]++
		}
		if e.Time.After(c.Last) {
			c.Last = e.Time
		}
	}
	cl, ok := t.client[e.IP]
	if !ok {
		cl = &Client{IP: e.IP, Users: map[string]bool{}}
		t.client[e.IP] = cl
	}
	cl.Downloads++
	cl.Bytes += e.Bytes
	cl.Users[e.User] = true
	if e.Time.After(cl.Last) {
		cl.Last = e.Time
		cl.Agent = e.Agent
	}
}

// Top rend les paquets les plus téléchargés (repo vide : tous).
func (t *Tracker) Top(repo string, n int, allowed func(repo string) bool) []Counter {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []Counter
	for _, c := range t.stats {
		if (repo == "" || c.Repo == repo) && allowed(c.Repo) {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Downloads != out[j].Downloads {
			return out[i].Downloads > out[j].Downloads
		}
		return out[i].Name < out[j].Name
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// For rend le compteur d'un paquet.
func (t *Tracker) For(repo, name string) (Counter, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	c, ok := t.stats[repo+"\x00"+name]
	if !ok {
		return Counter{}, false
	}
	return *c, true
}

// Recent rend les derniers évènements, du plus récent au plus ancien.
func (t *Tracker) Recent(n int, filter func(Event) bool) []Event {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []Event
	for i := len(t.recent) - 1; i >= 0 && (n <= 0 || len(out) < n); i-- {
		if filter == nil || filter(t.recent[i]) {
			out = append(out, t.recent[i])
		}
	}
	return out
}

// Days rend les n derniers jours (du plus ancien au plus récent), jours vides compris.
func (t *Tracker) Days(n int) []Day {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Day, 0, n)
	now := time.Now().UTC()
	for i := n - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		if day, ok := t.daily[d]; ok {
			out = append(out, *day)
		} else {
			out = append(out, Day{Date: d})
		}
	}
	return out
}

// Clients rend les adresses les plus actives.
func (t *Tracker) Clients(n int) []Client {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Client, 0, len(t.client))
	for _, c := range t.client {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Totals rend les totaux sur les n derniers jours.
func (t *Tracker) Totals(days int) Day {
	var tot Day
	for _, d := range t.Days(days) {
		tot.Downloads += d.Downloads
		tot.Uploads += d.Uploads
		tot.Bytes += d.Bytes
		tot.Denied += d.Denied
	}
	return tot
}

// Export écrit les évènements d'une période en JSON Lines.
func (t *Tracker) Export(w *bufio.Writer, from, to time.Time, filter func(Event) bool) error {
	for d := from.UTC().Truncate(24 * time.Hour); !d.After(to); d = d.AddDate(0, 0, 1) {
		f, err := os.Open(filepath.Join(t.dir, d.Format("2006-01-02")+".jsonl"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			var e Event
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			if e.Time.Before(from) || e.Time.After(to) || (filter != nil && !filter(e)) {
				continue
			}
			w.Write(sc.Bytes())
			w.WriteByte('\n')
		}
		f.Close()
	}
	return w.Flush()
}

// anonymize tronque une adresse (/24 en IPv4, /48 en IPv6).
func anonymize(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	if v4 := p.To4(); v4 != nil {
		return net.IP(v4.Mask(net.CIDRMask(24, 32))).String()
	}
	return p.Mask(net.CIDRMask(48, 128)).String()
}
