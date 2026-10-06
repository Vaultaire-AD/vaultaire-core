package ldapstorage

import (
	"strconv"
	"strings"
)

// Les formes TEXTE d'un filtre et d'un code de résultat, pour le journal —
// TO-DO 145.
//
// Rangées ici, à côté des structures qu'elles décrivent : le journal d'une
// opération tient sur une ligne, et il lui faut le filtre tel que
// l'administrateur l'a saisi chez son client, pas un arbre sur dix lignes.

// nomsDesResultats porte le nom RFC 4511 de chaque code que le serveur émet.
//
// Les noms sont ceux de la norme, en anglais : c'est sous cette forme qu'on les
// retrouve dans les journaux du client, et c'est là qu'on ira les comparer.
var nomsDesResultats = map[int]string{
	ResultSuccess:                      "success",
	ResultOperationsError:              "operationsError",
	ResultProtocolError:                "protocolError",
	ResultTimeLimitExceeded:            "timeLimitExceeded",
	ResultSizeLimitExceeded:            "sizeLimitExceeded",
	ResultAuthMethodNotSupported:       "authMethodNotSupported",
	ResultStrongerAuthRequired:         "strongerAuthRequired",
	ResultUnavailableCriticalExtension: "unavailableCriticalExtension",
	ResultInappropriateMatching:        "inappropriateMatching",
	ResultNoSuchObject:                 "noSuchObject",
	ResultInvalidCredentials:           "invalidCredentials",
	ResultInsufficientAccessRights:     "insufficientAccessRights",
	ResultBusy:                         "busy",
	ResultUnwillingToPerform:           "unwillingToPerform",
}

// NomDuResultat rend « 49 invalidCredentials ». Un code sans nom connu est
// rendu seul : mieux vaut un nombre nu qu'un nom inventé.
func NomDuResultat(code int) string {
	if nom, connu := nomsDesResultats[code]; connu {
		return strconv.Itoa(code) + " " + nom
	}
	return strconv.Itoa(code)
}

// NomDeLaPortee rend base, one ou sub — les mots de `ldapsearch -s`.
func NomDeLaPortee(scope int) string {
	switch scope {
	case 0:
		return "base"
	case 1:
		return "one"
	case 2:
		return "sub"
	}
	return strconv.Itoa(scope)
}

// Texte rend le filtre sous sa forme de chaîne — RFC 4515 :
// « (&(objectClass=person)(uid=al*)) ».
//
// C'est la forme que l'administrateur a écrite dans la configuration de son
// client : il la reconnaît, et peut la rejouer telle quelle avec `ldapsearch`.
//
// Les valeurs sont échappées comme le veut la RFC (`*`, `(`, `)`, `\`, NUL) :
// la ligne doit rester un filtre VALIDE, et une valeur contenant une
// parenthèse ne doit pas pouvoir faire lire autre chose que ce qui a été
// demandé.
//
// Les caractères de CONTRÔLE et le guillemet le sont aussi, par la même
// notation `\xx`. Ce texte part dans un journal, et il vient d'un client : un
// retour à la ligne dans une valeur de filtre permettrait d'y écrire une
// fausse ligne.
func (f *LDAPFilter) Texte() string {
	if f == nil {
		return "(objectClass=*)"
	}
	var sb strings.Builder
	f.ecrire(&sb)
	return sb.String()
}

func (f *LDAPFilter) ecrire(sb *strings.Builder) {
	if f == nil {
		return
	}
	sb.WriteByte('(')
	switch f.Type {
	case FilterAnd, FilterOr, FilterNot:
		switch f.Type {
		case FilterAnd:
			sb.WriteByte('&')
		case FilterOr:
			sb.WriteByte('|')
		default:
			sb.WriteByte('!')
		}
		for _, sous := range f.SubFilters {
			sous.ecrire(sb)
		}
	case FilterPresent:
		sb.WriteString(echapperValeur(f.Attribute) + "=*")
	case FilterSubstring:
		sb.WriteString(echapperValeur(f.Attribute) + "=" + echapperValeur(f.SubInitial))
		for _, morceau := range f.SubAny {
			sb.WriteString("*" + echapperValeur(morceau))
		}
		sb.WriteString("*" + echapperValeur(f.SubFinal))
	case FilterGreaterOrEqual:
		sb.WriteString(echapperValeur(f.Attribute) + ">=" + echapperValeur(f.Value))
	case FilterLessOrEqual:
		sb.WriteString(echapperValeur(f.Attribute) + "<=" + echapperValeur(f.Value))
	case FilterApprox:
		sb.WriteString(echapperValeur(f.Attribute) + "~=" + echapperValeur(f.Value))
	case FilterExtensible:
		sb.WriteString(echapperValeur(f.Attribute) + ":=" + echapperValeur(f.Value))
	default:
		// L'égalité, et tout type à venir : attribut et valeur disent déjà
		// l'essentiel.
		sb.WriteString(echapperValeur(f.Attribute) + "=" + echapperValeur(f.Value))
	}
	sb.WriteByte(')')
}

// echapperValeur applique l'échappement de la RFC 4515 §3, étendu aux
// caractères de contrôle et au guillemet.
func echapperValeur(v string) string {
	propre := true
	for i := 0; i < len(v) && propre; i++ {
		propre = !aEchapper(v[i])
	}
	if propre {
		return v
	}
	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		if c := v[i]; aEchapper(c) {
			sb.WriteString(`\` + strconv.FormatInt(int64(c)+0x100, 16)[1:])
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func aEchapper(c byte) bool {
	switch c {
	case '*', '(', ')', '\\', '"', 0x7f:
		return true
	}
	return c < 0x20
}
