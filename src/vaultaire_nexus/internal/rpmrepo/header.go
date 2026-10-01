// Package rpmrepo lit les paquets RPM et produit les métadonnées d'un dépôt
// YUM/DNF (repodata/), sans createrepo.
//
// # Format d'un fichier RPM
//
//	lead            96 octets, historique, ignoré sauf la signature magique
//	signature       un en-tête (même structure que ci-dessous), aligné sur 8
//	header          l'en-tête du paquet : nom, version, dépendances, fichiers…
//	payload         l'archive cpio compressée — jamais lue ici
//
// Un en-tête est : magique (3 octets) + version (1) + réservé (4), nombre
// d'entrées (4, big-endian), taille du magasin (4), puis les entrées d'index
// (16 octets : tag, type, décalage, nombre), puis le magasin de données.
package rpmrepo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Tags utilisés.
const (
	tagName            = 1000
	tagVersion         = 1001
	tagRelease         = 1002
	tagEpoch           = 1003
	tagSummary         = 1004
	tagDescription     = 1005
	tagBuildTime       = 1006
	tagBuildHost       = 1007
	tagSize            = 1009
	tagVendor          = 1011
	tagLicense         = 1014
	tagPackager        = 1015
	tagGroup           = 1016
	tagURL             = 1020
	tagArch            = 1022
	tagOldFilenames    = 1027
	tagFileSizes       = 1028
	tagFileModes       = 1030
	tagFileFlags       = 1037
	tagSourceRPM       = 1044
	tagArchiveSize     = 1046
	tagProvideName     = 1047
	tagRequireFlags    = 1048
	tagRequireName     = 1049
	tagRequireVersion  = 1050
	tagConflictFlags   = 1053
	tagConflictName    = 1054
	tagConflictVersion = 1055
	tagObsoleteName    = 1090
	tagProvideFlags    = 1112
	tagProvideVersion  = 1113
	tagObsoleteFlags   = 1114
	tagObsoleteVersion = 1115
	tagDirIndexes      = 1116
	tagBaseNames       = 1117
	tagDirNames        = 1118
	tagSourcePackage   = 1106
	tagLongArchiveSize = 271
	tagLongSize        = 5009
)

// Types de données.
const (
	typeInt8        = 2
	typeInt16       = 3
	typeInt32       = 4
	typeInt64       = 5
	typeString      = 6
	typeBin         = 7
	typeStringArray = 8
	typeI18NString  = 9
)

// Drapeaux de dépendance.
const (
	senseLess       = 1 << 1
	senseGreater    = 1 << 2
	senseEqual      = 1 << 3
	sensePrereq     = 1 << 6
	senseScriptPre  = 1 << 9
	senseScriptPost = 1 << 10
	senseRPMLib     = 1 << 24
)

const fileFlagGhost = 1 << 6

var (
	leadMagic   = []byte{0xed, 0xab, 0xee, 0xdb}
	headerMagic = []byte{0x8e, 0xad, 0xe8}
)

// Entry est une dépendance (provides, requires…).
type Entry struct {
	Name  string `json:"name"`
	Flags string `json:"flags,omitempty"` // EQ, LT, LE, GT, GE
	Epoch string `json:"epoch,omitempty"`
	Ver   string `json:"ver,omitempty"`
	Rel   string `json:"rel,omitempty"`
	Pre   bool   `json:"pre,omitempty"`
}

// File est un fichier du paquet.
type File struct {
	Path  string `json:"path"`
	Dir   bool   `json:"dir,omitempty"`
	Ghost bool   `json:"ghost,omitempty"`
}

// Package est ce que repodata a besoin de savoir d'un RPM.
type Package struct {
	Name          string  `json:"name"`
	Epoch         string  `json:"epoch"`
	Version       string  `json:"version"`
	Release       string  `json:"release"`
	Arch          string  `json:"arch"`
	Summary       string  `json:"summary"`
	Description   string  `json:"description"`
	Packager      string  `json:"packager,omitempty"`
	URL           string  `json:"url,omitempty"`
	License       string  `json:"license,omitempty"`
	Vendor        string  `json:"vendor,omitempty"`
	Group         string  `json:"group,omitempty"`
	BuildHost     string  `json:"buildhost,omitempty"`
	SourceRPM     string  `json:"sourcerpm,omitempty"`
	BuildTime     int64   `json:"buildtime"`
	InstalledSize int64   `json:"installed_size"`
	ArchiveSize   int64   `json:"archive_size"`
	HeaderStart   int64   `json:"header_start"`
	HeaderEnd     int64   `json:"header_end"`
	Provides      []Entry `json:"provides,omitempty"`
	Requires      []Entry `json:"requires,omitempty"`
	Conflicts     []Entry `json:"conflicts,omitempty"`
	Obsoletes     []Entry `json:"obsoletes,omitempty"`
	Files         []File  `json:"files,omitempty"`
	IsSource      bool    `json:"is_source,omitempty"`
}

// FullVersion rend « [epoch:]version-release ».
func (p Package) FullVersion() string {
	v := p.Version + "-" + p.Release
	if p.Epoch != "" && p.Epoch != "0" {
		v = p.Epoch + ":" + v
	}
	return v
}

// CanonicalFilename rend le nom attendu : name-version-release.arch.rpm.
func (p Package) CanonicalFilename() string {
	arch := p.Arch
	if p.IsSource {
		arch = "src"
	}
	return fmt.Sprintf("%s-%s-%s.%s.rpm", p.Name, p.Version, p.Release, arch)
}

type header struct {
	tags  map[int32]indexEntry
	store []byte
}

type indexEntry struct {
	typ    int32
	offset int32
	count  int32
}

const maxHeaderBytes = 64 << 20 // un en-tête de 64 Mo n'existe pas ; au-delà, fichier hostile

// readHeader lit un en-tête à la position courante ; rend le nombre d'octets lus.
func readHeader(r io.Reader) (*header, int64, error) {
	var pre [16]byte
	if _, err := io.ReadFull(r, pre[:]); err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(pre[:3], headerMagic) {
		return nil, 0, errors.New("en-tête RPM : signature magique absente")
	}
	nindex := int64(binary.BigEndian.Uint32(pre[8:12]))
	hsize := int64(binary.BigEndian.Uint32(pre[12:16]))
	if nindex > 100000 || nindex*16+hsize > maxHeaderBytes {
		return nil, 0, errors.New("en-tête RPM : taille déraisonnable")
	}
	idx := make([]byte, nindex*16)
	if _, err := io.ReadFull(r, idx); err != nil {
		return nil, 0, err
	}
	h := &header{tags: make(map[int32]indexEntry, nindex), store: make([]byte, hsize)}
	if _, err := io.ReadFull(r, h.store); err != nil {
		return nil, 0, err
	}
	for i := int64(0); i < nindex; i++ {
		e := idx[i*16 : i*16+16]
		tag := int32(binary.BigEndian.Uint32(e[0:4]))
		ie := indexEntry{
			typ:    int32(binary.BigEndian.Uint32(e[4:8])),
			offset: int32(binary.BigEndian.Uint32(e[8:12])),
			count:  int32(binary.BigEndian.Uint32(e[12:16])),
		}
		if ie.offset < 0 || int64(ie.offset) > hsize || ie.count < 0 {
			return nil, 0, fmt.Errorf("en-tête RPM : entrée %d hors limites", tag)
		}
		h.tags[tag] = ie
	}
	return h, 16 + nindex*16 + hsize, nil
}

func (h *header) strings(tag int32) []string {
	e, ok := h.tags[tag]
	if !ok {
		return nil
	}
	switch e.typ {
	case typeString, typeStringArray, typeI18NString:
	default:
		return nil
	}
	n := int(e.count)
	if e.typ == typeString {
		n = 1
	}
	out := make([]string, 0, n)
	pos := int(e.offset)
	for i := 0; i < n && pos < len(h.store); i++ {
		end := bytes.IndexByte(h.store[pos:], 0)
		if end < 0 {
			break
		}
		out = append(out, string(h.store[pos:pos+end]))
		pos += end + 1
	}
	return out
}

func (h *header) str(tag int32) string {
	s := h.strings(tag)
	if len(s) == 0 {
		return ""
	}
	return s[0] // I18N : la première traduction est la version C
}

func (h *header) ints(tag int32) []int64 {
	e, ok := h.tags[tag]
	if !ok {
		return nil
	}
	var width int
	switch e.typ {
	case typeInt8:
		width = 1
	case typeInt16:
		width = 2
	case typeInt32:
		width = 4
	case typeInt64:
		width = 8
	default:
		return nil
	}
	start := int(e.offset)
	end := start + width*int(e.count)
	if end > len(h.store) {
		return nil
	}
	out := make([]int64, e.count)
	for i := range out {
		b := h.store[start+i*width:]
		switch width {
		case 1:
			out[i] = int64(b[0])
		case 2:
			out[i] = int64(binary.BigEndian.Uint16(b))
		case 4:
			out[i] = int64(binary.BigEndian.Uint32(b))
		case 8:
			out[i] = int64(binary.BigEndian.Uint64(b))
		}
	}
	return out
}

func (h *header) int(tag int32) (int64, bool) {
	v := h.ints(tag)
	if len(v) == 0 {
		return 0, false
	}
	return v[0], true
}

// Parse lit un RPM (lead, signature, en-tête) depuis r, sans lire le payload.
func Parse(r io.Reader) (*Package, error) {
	var lead [96]byte
	if _, err := io.ReadFull(r, lead[:]); err != nil {
		return nil, fmt.Errorf("RPM trop court : %w", err)
	}
	if !bytes.Equal(lead[:4], leadMagic) {
		return nil, errors.New("ce fichier n'est pas un paquet RPM")
	}
	isSource := binary.BigEndian.Uint16(lead[6:8]) == 1

	_, sigLen, err := readHeader(r)
	if err != nil {
		return nil, fmt.Errorf("signature : %w", err)
	}
	pos := int64(96) + sigLen
	if pad := (8 - sigLen%8) % 8; pad > 0 {
		if _, err := io.CopyN(io.Discard, r, pad); err != nil {
			return nil, err
		}
		pos += pad
	}
	h, hLen, err := readHeader(r)
	if err != nil {
		return nil, fmt.Errorf("en-tête : %w", err)
	}

	p := &Package{
		Name:        h.str(tagName),
		Version:     h.str(tagVersion),
		Release:     h.str(tagRelease),
		Arch:        h.str(tagArch),
		Summary:     h.str(tagSummary),
		Description: h.str(tagDescription),
		Packager:    h.str(tagPackager),
		URL:         h.str(tagURL),
		License:     h.str(tagLicense),
		Vendor:      h.str(tagVendor),
		Group:       h.str(tagGroup),
		BuildHost:   h.str(tagBuildHost),
		SourceRPM:   h.str(tagSourceRPM),
		HeaderStart: pos,
		HeaderEnd:   pos + hLen,
		IsSource:    isSource,
		Epoch:       "0",
	}
	if _, ok := h.tags[tagSourcePackage]; ok {
		p.IsSource = true
	}
	if p.Name == "" || p.Version == "" || p.Release == "" {
		return nil, errors.New("en-tête RPM incomplet : nom, version ou release manquant")
	}
	if e, ok := h.int(tagEpoch); ok {
		p.Epoch = strconv.FormatInt(e, 10)
	}
	if v, ok := h.int(tagBuildTime); ok {
		p.BuildTime = v
	}
	if v, ok := h.int(tagLongSize); ok {
		p.InstalledSize = v
	} else if v, ok := h.int(tagSize); ok {
		p.InstalledSize = v
	}
	if v, ok := h.int(tagLongArchiveSize); ok {
		p.ArchiveSize = v
	} else if v, ok := h.int(tagArchiveSize); ok {
		p.ArchiveSize = v
	}

	p.Provides = deps(h, tagProvideName, tagProvideFlags, tagProvideVersion, false)
	p.Requires = deps(h, tagRequireName, tagRequireFlags, tagRequireVersion, true)
	p.Conflicts = deps(h, tagConflictName, tagConflictFlags, tagConflictVersion, false)
	p.Obsoletes = deps(h, tagObsoleteName, tagObsoleteFlags, tagObsoleteVersion, false)
	p.Files = files(h)
	return p, nil
}

func deps(h *header, nameTag, flagTag, verTag int32, requires bool) []Entry {
	names := h.strings(nameTag)
	flags := h.ints(flagTag)
	vers := h.strings(verTag)
	var out []Entry
	seen := map[string]bool{}
	for i, n := range names {
		var fl int64
		if i < len(flags) {
			fl = flags[i]
		}
		if requires && (fl&senseRPMLib != 0 || strings.HasPrefix(n, "rpmlib(")) {
			continue // dépendances internes à rpm : createrepo les omet aussi
		}
		e := Entry{Name: n}
		if i < len(vers) && vers[i] != "" {
			e.Epoch, e.Ver, e.Rel = splitEVR(vers[i])
			e.Flags = flagString(fl)
		}
		if requires && fl&(sensePrereq|senseScriptPre|senseScriptPost) != 0 {
			e.Pre = true
		}
		key := fmt.Sprintf("%s|%s|%s|%s|%s|%v", e.Name, e.Flags, e.Epoch, e.Ver, e.Rel, e.Pre)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out
}

func flagString(fl int64) string {
	switch fl & (senseLess | senseGreater | senseEqual) {
	case senseEqual:
		return "EQ"
	case senseLess:
		return "LT"
	case senseLess | senseEqual:
		return "LE"
	case senseGreater:
		return "GT"
	case senseGreater | senseEqual:
		return "GE"
	}
	return ""
}

// splitEVR découpe « [epoch:]version[-release] ».
func splitEVR(s string) (epoch, ver, rel string) {
	epoch = "0"
	if i := strings.IndexByte(s, ':'); i >= 0 {
		epoch, s = s[:i], s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		return epoch, s[:i], s[i+1:]
	}
	return epoch, s, ""
}

func files(h *header) []File {
	var paths []string
	if base := h.strings(tagBaseNames); len(base) > 0 {
		dirs := h.strings(tagDirNames)
		idx := h.ints(tagDirIndexes)
		for i, b := range base {
			if i < len(idx) && int(idx[i]) < len(dirs) {
				paths = append(paths, dirs[idx[i]]+b)
			}
		}
	} else {
		paths = h.strings(tagOldFilenames)
	}
	modes := h.ints(tagFileModes)
	flags := h.ints(tagFileFlags)
	out := make([]File, len(paths))
	for i, p := range paths {
		f := File{Path: p}
		if i < len(modes) && (modes[i]&0o170000) == 0o040000 {
			f.Dir = true
		}
		if i < len(flags) && flags[i]&fileFlagGhost != 0 {
			f.Ghost = true
		}
		out[i] = f
	}
	return out
}
