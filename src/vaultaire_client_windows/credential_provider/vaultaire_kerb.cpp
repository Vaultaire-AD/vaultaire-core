#include "vaultaire_kerb.h"
#include "vaultaire_pipe.h"

#include <ntsecapi.h>
#include <wincred.h>

// NEGOSSP_NAME_A (« Negotiate ») est déclaré par l'en-tête SSPI, que
// credentialprovider.h n'apporte pas. SECURITY_WIN32 dit à sspi.h pour quelle
// plateforme les déclarations sont voulues — sans lui, l'en-tête ne déclare
// rien et l'erreur porte sur le symbole, pas sur sa cause.
#define SECURITY_WIN32
#include <security.h>

namespace vaultaire {
namespace {

// PoserChaine remplit une UNICODE_STRING à partir d'un std::wstring.
//
// La longueur est en OCTETS, pas en caractères — la confusion donne un bloc
// tronqué de moitié, et un refus d'ouverture de session sans explication.
void PoserChaine(UNICODE_STRING* cible, const std::wstring& valeur) {
  cible->Length = (USHORT)(valeur.size() * sizeof(wchar_t));
  cible->MaximumLength = (USHORT)((valeur.size() + 1) * sizeof(wchar_t));
  cible->Buffer = const_cast<wchar_t*>(valeur.c_str());
}

// RendreRelatif transforme un pointeur absolu en DÉPLACEMENT depuis le début du
// bloc, et recopie la chaîne à la suite.
//
// C'est la particularité de la sérialisation attendue par LSA : le bloc est
// copié d'un processus à l'autre, donc aucun pointeur absolu n'y survivrait.
// Le champ Buffer d'une UNICODE_STRING y porte un déplacement, pas une adresse.
void RendreRelatif(BYTE* base, ULONG* curseur, UNICODE_STRING* chaine) {
  if (chaine->Length == 0) {
    chaine->Buffer = nullptr;
    return;
  }
  CopyMemory(base + *curseur, chaine->Buffer, chaine->Length);
  chaine->Buffer = (wchar_t*)(ULONG_PTR)(*curseur);
  *curseur += chaine->Length;
}

// PaquetNegocier rend l'identifiant du paquet d'authentification « Negotiate ».
//
// Winlogon exige un numéro de paquet valide ; celui de Negotiate laisse LSA
// choisir entre Kerberos et NTLM. Pour un compte LOCAL, ce sera NTLM — mais
// écrire NTLM en dur ferait échouer le jour où ce même fournisseur servira un
// compte de domaine.
HRESULT PaquetNegocier(ULONG* paquet) {
  HANDLE lsa = nullptr;
  NTSTATUS etat = LsaConnectUntrusted(&lsa);
  if (etat != 0) return HRESULT_FROM_NT(etat);

  LSA_STRING nom;
  nom.Buffer = const_cast<char*>(NEGOSSP_NAME_A);
  nom.Length = (USHORT)strlen(NEGOSSP_NAME_A);
  nom.MaximumLength = (USHORT)(nom.Length + 1);

  etat = LsaLookupAuthenticationPackage(lsa, &nom, paquet);
  LsaDeregisterLogonProcess(lsa);
  return etat == 0 ? S_OK : HRESULT_FROM_NT(etat);
}

}  // namespace

std::wstring NomDeCetteMachine() {
  wchar_t nom[MAX_COMPUTERNAME_LENGTH + 1] = {0};
  DWORD taille = MAX_COMPUTERNAME_LENGTH + 1;
  if (!GetComputerNameW(nom, &taille)) return std::wstring(L".");
  return std::wstring(nom);
}

HRESULT PreparerBlocOuverture(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
                              const std::wstring& domaine,
                              const std::wstring& utilisateur,
                              const std::wstring& mot_de_passe,
                              CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* sortie) {
  KERB_INTERACTIVE_UNLOCK_LOGON logon = {};

  // Le TYPE de message décide de ce que LSA fait du bloc : ouvrir une session,
  // ou déverrouiller celle qui existe. Se tromper ici ouvre une seconde session
  // là où l'utilisateur croyait retrouver la sienne.
  logon.Logon.MessageType = (scenario == CPUS_UNLOCK_WORKSTATION)
                                ? KerbWorkstationUnlockLogon
                                : KerbInteractiveLogon;

  PoserChaine(&logon.Logon.LogonDomainName, domaine);
  PoserChaine(&logon.Logon.UserName, utilisateur);
  PoserChaine(&logon.Logon.Password, mot_de_passe);

  const ULONG taille = sizeof(logon) + logon.Logon.LogonDomainName.Length +
                       logon.Logon.UserName.Length + logon.Logon.Password.Length;

  BYTE* bloc = (BYTE*)CoTaskMemAlloc(taille);
  if (bloc == nullptr) return E_OUTOFMEMORY;
  ZeroMemory(bloc, taille);

  // L'en-tête d'abord, les chaînes ensuite : le curseur part donc juste après
  // la structure.
  ULONG curseur = sizeof(logon);
  KERB_INTERACTIVE_UNLOCK_LOGON* entete = (KERB_INTERACTIVE_UNLOCK_LOGON*)bloc;
  *entete = logon;
  RendreRelatif(bloc, &curseur, &entete->Logon.LogonDomainName);
  RendreRelatif(bloc, &curseur, &entete->Logon.UserName);
  RendreRelatif(bloc, &curseur, &entete->Logon.Password);

  ULONG paquet = 0;
  HRESULT hr = PaquetNegocier(&paquet);
  if (FAILED(hr)) {
    // Le bloc contient le mot de passe : il est effacé, pas seulement libéré.
    SecureZeroMemory(bloc, taille);
    CoTaskMemFree(bloc);
    Journaliser(L"paquet d'authentification introuvable (0x%08lx)", hr);
    return hr;
  }

  sortie->ulAuthenticationPackage = paquet;
  sortie->clsidCredentialProvider = GUID_NULL;  // rempli par l'appelant
  sortie->cbSerialization = taille;
  sortie->rgbSerialization = bloc;
  return S_OK;
}

}  // namespace vaultaire
