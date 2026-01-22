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
        // Log de debug pour voir ce qui passe réellement
        // fmt.Printf("Tag: %d, Class: %d, Data: %v\n", p.Tag, p.ClassType, p.Value)

        // Cas 1 : EqualityMatch (Tag 3) -> (attr=val)
        if p.Tag == 3 && p.ClassType == ber.ClassContext {
            if len(p.Children) == 2 {
                attr, ok1 := p.Children[0].Value.(string)
                val, ok2 := p.Children[1].Value.(string)
                if ok1 && ok2 {
                    filters = append(filters, ldapstorage.EqualityFilter{
                        Attribute: attr,
                        Value:     val,
                    })
                }
            }
        } else if p.Tag == 7 && p.ClassType == ber.ClassContext {
            // Cas 2 : PresentMatch (Tag 7) -> (attr=*)
            // ATTENTION : Parfois le contenu est dans p.Data.Bytes() ou p.ByteValue
            // On essaie de récupérer le nom de l'attribut (ex: "objectclass")
            attr := p.Data.String() 
            if attr == "" {
                attr = fmt.Sprintf("%s", p.Value)
            }

            if attr != "" {
                fmt.Printf("Filtre 'Present' détecté : (%s=*)\n", attr)
                filters = append(filters, ldapstorage.EqualityFilter{
                    Attribute: attr,
                    Value:     "*",
                })
            }
        }

        // Toujours explorer les enfants, même si on a trouvé un match au cas où
        // ou pour descendre dans les structures AND (0)/OR (1)/NOT (2)
        for _, child := range p.Children {
            walk(child)
        }
    }

    if packet == nil { return nil, fmt.Errorf("nil packet") }
    walk(packet)
    return filters, nil
}
