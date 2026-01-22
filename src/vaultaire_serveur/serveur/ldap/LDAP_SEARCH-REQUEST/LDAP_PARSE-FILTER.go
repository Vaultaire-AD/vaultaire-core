package ldapsearchrequest

import (
	ldapstorage "DUCKY/serveur/ldap/LDAP_Storage"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func ExtractEqualityFilters(packet *ber.Packet) ([]ldapstorage.EqualityFilter, error) {
    var filters []ldapstorage.EqualityFilter

    var walk func(p *ber.Packet)
    walk = func(p *ber.Packet) {
        // Cas 1 : EqualityMatch (Tag 3) -> (attr=val)
        if p.Tag == 3 && p.ClassType == ber.ClassContext && len(p.Children) == 2 {
            attr, ok1 := p.Children[0].Value.(string)
            val, ok2 := p.Children[1].Value.(string)
            if ok1 && ok2 {
                filters = append(filters, ldapstorage.EqualityFilter{
                    Attribute: attr,
                    Value:     val,
                })
            }
        } else if p.Tag == 7 && p.ClassType == ber.ClassContext {
            // Cas 2 : PresentMatch (Tag 7) -> (attr=*)
            // La valeur est directement dans p.Value
            if attr, ok := p.Value.(string); ok {
                fmt.Printf("Filtre 'Present' détecté sur l'attribut : %s\n", attr)
                // Tu peux choisir d'ajouter une valeur spéciale comme "*"
                filters = append(filters, ldapstorage.EqualityFilter{
                    Attribute: attr,
                    Value:     "*",
                })
            }
        } else {
            // Traverse les enfants pour les filtres composés (AND=0, OR=1, NOT=2)
            for _, child := range p.Children {
                walk(child)
            }
        }
    }

    if packet == nil { return nil, fmt.Errorf("nil packet") }
    walk(packet)
    return filters, nil
}
