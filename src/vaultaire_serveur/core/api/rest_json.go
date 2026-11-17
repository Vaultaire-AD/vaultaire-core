package api

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
)

// Un JSON propre à partir des données des actions — TO-DO 270.
//
// # Le problème
//
// Les actions rendent leurs données dans les types du code (`storage.GetUsers`,
// `storage.GroupDetails`…), écrits pour l'affichage en ligne de commande. La
// plupart n'ont pas de balise `json` : encodés tels quels, ils donneraient
// `{"GroupName": …, "Database_portDatabase": …}` — la forme interne du code,
// qui changerait à chaque renommage d'un champ Go.
//
// Baliser les quelque cent types concernés serait un chantier, et chaque type
// ajouté demain l'oublierait. La conversion se fait donc ICI, une fois :
//
//   - un champ de structure prend le nom de sa balise `json` s'il en a une,
//     sinon son nom en snake_case : `GroupName` → `group_name`, `ID` → `id`,
//     `UserID` → `user_id`, `DNSName` → `dns_name` ;
//   - les CLÉS DE MAP ne sont jamais renommées : ce sont des données (un nom de
//     compte, un domaine), pas des noms de champ ;
//   - une liste nulle devient `[]` et une map nulle `{}` : un client n'a pas à
//     distinguer « aucun élément » de « rien » ;
//   - `time.Time` en RFC 3339, nul si la date est zéro ; `sql.Null*` en leur
//     valeur, ou nul ; une erreur en son message ;
//   - un type qui sait s'encoder lui-même (json.Marshaler) le fait.

// versJSON rend une valeur prête pour encoding/json.
func versJSON(v any) any {
	return convertir(reflect.ValueOf(v), 0)
}

// profondeurMax borne la récursion : une structure qui se référence
// elle-même ne doit pas épuiser la pile du serveur.
const profondeurMax = 32

var (
	typeTemps     = reflect.TypeOf(time.Time{})
	typeMarshaler = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	typeValuer    = reflect.TypeOf((*driver.Valuer)(nil)).Elem()
	typeErreur    = reflect.TypeOf((*error)(nil)).Elem()
)

func convertir(v reflect.Value, profondeur int) any {
	if !v.IsValid() || !v.CanInterface() {
		// Atteint par un champ d'une structure embarquée non exportée : sa
		// valeur ne se lit pas par réflexion, et encoding/json l'ignorerait.
		return nil
	}
	if profondeur > profondeurMax {
		return fmt.Sprintf("<profondeur > %d>", profondeurMax)
	}

	// Pointeurs et interfaces : on suit, nul reste nul.
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	t := v.Type()
	switch {
	case t == typeTemps:
		tm := v.Interface().(time.Time)
		if tm.IsZero() {
			return nil
		}
		return tm.Format(time.RFC3339)
	case t.Implements(typeErreur):
		return v.Interface().(error).Error()
	case t.Implements(typeMarshaler):
		return v.Interface()
	case t.Implements(typeValuer):
		val, err := v.Interface().(driver.Valuer).Value()
		if err != nil || val == nil {
			return nil
		}
		return convertir(reflect.ValueOf(val), profondeur+1)
	}

	switch v.Kind() {
	case reflect.Struct:
		out := make(map[string]any, t.NumField())
		convertirChamps(v, out, profondeur)
		return out

	case reflect.Map:
		out := make(map[string]any, v.Len())
		if v.IsNil() {
			return out
		}
		iter := v.MapRange()
		for iter.Next() {
			out[fmt.Sprint(iter.Key().Interface())] = convertir(iter.Value(), profondeur+1)
		}
		return out

	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			// []byte : encoding/json le rend en base64, comme attendu.
			return v.Bytes()
		}
		if v.IsNil() {
			return []any{}
		}
		fallthrough
	case reflect.Array:
		out := make([]any, v.Len())
		for i := range v.Len() {
			out[i] = convertir(v.Index(i), profondeur+1)
		}
		return out

	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return nil
	}
	return v.Interface()
}

// convertirChamps verse les champs exportés d'une structure dans out.
//
// Un champ ANONYME sans balise est aplati, comme le fait encoding/json : ses
// champs deviennent ceux de la structure qui l'embarque.
func convertirChamps(v reflect.Value, out map[string]any, profondeur int) {
	t := v.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			// Y compris une structure embarquée non exportée : ses champs ne se
			// lisent pas par réflexion depuis ce paquet.
			continue
		}
		nom, omettreSiVide, ignorer := nomChampJSON(f)
		if ignorer {
			continue
		}
		fv := v.Field(i)
		if f.Anonymous && f.Tag.Get("json") == "" {
			for fv.Kind() == reflect.Pointer {
				if fv.IsNil() {
					break
				}
				fv = fv.Elem()
			}
			if fv.Kind() == reflect.Struct && fv.Type() != typeTemps {
				convertirChamps(fv, out, profondeur+1)
				continue
			}
		}
		if omettreSiVide && fv.IsZero() {
			continue
		}
		out[nom] = convertir(fv, profondeur+1)
	}
}

// nomChampJSON lit la balise json d'un champ, ou dérive le snake_case.
func nomChampJSON(f reflect.StructField) (nom string, omettreSiVide, ignorer bool) {
	balise := f.Tag.Get("json")
	if balise == "-" {
		return "", false, true
	}
	partie, options, _ := strings.Cut(balise, ",")
	omettreSiVide = strings.Contains(","+options+",", ",omitempty,")
	if partie != "" {
		return partie, omettreSiVide, false
	}
	return SnakeCase(f.Name), omettreSiVide, false
}

// SnakeCase convertit un nom de champ Go : `GroupName` → `group_name`,
// `UserID` → `user_id`, `DNSName` → `dns_name`, `Database_portDatabase` →
// `database_port_database`, `GPOs` → `gpos`.
//
// Une coupure est posée avant une majuscule qui suit une minuscule ou un
// chiffre (`groupName`), et avant la dernière majuscule d'un sigle suivie d'une
// minuscule (`DNSName` : `dns` / `name`). Les soulignés existants sont gardés,
// jamais doublés.
func SnakeCase(nom string) string {
	r := []rune(nom)
	var b strings.Builder
	for i, c := range r {
		if unicode.IsUpper(c) && i > 0 {
			prec := r[i-1]
			suivMin := i+1 < len(r) && unicode.IsLower(r[i+1])
			// Le pluriel d'un sigle n'ouvre pas un mot : « GPOs » → « gpos »,
			// « UserIDs » → « user_ids », et non « gp_os ».
			if suivMin && r[i+1] == 's' && (i+2 == len(r) || !unicode.IsLower(r[i+2])) {
				suivMin = false
			}
			if prec != '_' && (unicode.IsLower(prec) || unicode.IsDigit(prec) || (unicode.IsUpper(prec) && suivMin)) {
				b.WriteRune('_')
			}
		}
		if c == '_' && b.Len() > 0 && strings.HasSuffix(b.String(), "_") {
			continue
		}
		b.WriteRune(unicode.ToLower(c))
	}
	return b.String()
}
