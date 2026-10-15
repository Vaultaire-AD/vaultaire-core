// La sérialisation attendue par Winlogon.
//
// # Ce que Windows attend vraiment d'un Credential Provider
//
// Un Credential Provider ne « connecte » personne. Il RÉPOND à Winlogon avec un
// bloc d'identifiants sérialisé, que LSA passe ensuite au paquet
// d'authentification. Pour une session interactive locale, ce bloc est une
// structure KERB_INTERACTIVE_UNLOCK_LOGON : domaine, utilisateur, mot de passe.
//
// C'est pour cela que l'agent provisionne un compte local : le fournisseur rend
// ici un bloc ordinaire, et Windows ouvre une session ordinaire. Depuis le
// TO-DO 195, ce compte porte un secret de l'agent et non le mot de passe du
// domaine — sinon la tuile Windows du compte l'ouvrait sans Vaultaire. Aucun paquet d'authentification maison,
// aucune extension de LSA — c'est-à-dire aucun composant capable, en cassant,
// d'empêcher toute la machine de se connecter.
//
// # Pourquoi ces fonctions sont écrites à la main
//
// Elles n'appartiennent à aucune DLL : elles font partie des exemples du SDK,
// recopiés dans chaque fournisseur. Les voici, commentées, plutôt que copiées
// sans être comprises — la sérialisation utilise des pointeurs RELATIFS, et
// c'est exactement le genre de détail qui produit un échec de connexion sans
// message.

#pragma once

#include <windows.h>
#include <ntsecapi.h>
#include <credentialprovider.h>
#include <string>

namespace vaultaire {

// PreparerBlocOuverture compose le bloc d'identifiants d'une ouverture de
// session interactive.
//
//	domaine       nom NetBIOS de la machine (compte LOCAL)
//	utilisateur   le compte local provisionné par l'agent
//	mot_de_passe  le secret du compte local, rendu par l'agent (TO-DO 195) —
//	              jamais le mot de passe tapé, qui ne sert qu'au core
//
// Rend S_OK et remplit `sortie` (à libérer par CoTaskMemFree via le champ
// rgbSerialization), ou un HRESULT d'échec.
HRESULT PreparerBlocOuverture(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
                              const std::wstring& domaine,
                              const std::wstring& utilisateur,
                              const std::wstring& mot_de_passe,
                              CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* sortie);

// NomDeCetteMachine rend le nom NetBIOS, c'est-à-dire le « domaine » d'un
// compte local.
std::wstring NomDeCetteMachine();

}  // namespace vaultaire
