package duckynetwork

import (
	"fmt"
	"strings"
)

const (
	Trame01_01 = "01_01"
	Trame01_02 = "01_02"
	Trame04_01 = "04_01"
	Trame04_02 = "04_02"
	Trame04_03 = "04_03"
	Trame04_04 = "04_04"
	Trame04_07 = "04_07"
	Trame04_08 = "04_08"
)

// Frame représente une trame ducky-network standard.
type Frame struct {
	Code      string
	Target    string
	Session   string
	Username  string
	ClientID  string
	Content   string
	RawFields []string
}

// Build serialise une trame au format attendu par le protocole.
func (f Frame) Build() string {
	return strings.Join([]string{f.Code, f.Target, f.Session, f.Username, f.ClientID, f.Content}, "\n")
}

// ParseFrame parse une trame texte en structure.
func ParseFrame(payload string) (Frame, error) {
	lines := strings.Split(payload, "\n")
	if len(lines) < 5 {
		return Frame{}, fmt.Errorf("trame invalide: %d champs", len(lines))
	}
	content := ""
	if len(lines) > 5 {
		content = strings.Join(lines[5:], "\n")
	}
	return Frame{
		Code:      strings.TrimSpace(lines[0]),
		Target:    strings.TrimSpace(lines[1]),
		Session:   lines[2],
		Username:  lines[3],
		ClientID:  lines[4],
		Content:   content,
		RawFields: lines,
	}, nil
}
