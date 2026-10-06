// L'enveloppe COM : fabrique de classe, points d'entrée, inscription.
//
// # Comment Windows trouve ce fournisseur
//
//	HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32       -> chemin de la DLL
//	HKLM\...\Authentication\Credential Providers\{GUID}     -> « affiche-le »
//
// Les deux sont posées par DllRegisterServer (regsvr32) et retirées par
// DllUnregisterServer. L'inscription vit sous HKLM et non HKCU : l'écran de
// connexion s'affiche avant qu'aucun utilisateur ne soit connecté, donc avant
// qu'aucune ruche utilisateur ne soit chargée.

#include "vaultaire_guid.h"
#include "vaultaire_pipe.h"
#include "vaultaire_trace.h"

#include <windows.h>
#include <credentialprovider.h>
#include <new>
#include <stdio.h>
#include <string>

namespace vaultaire {
HRESULT CreerFournisseur(REFIID riid, void** ppv);
}

namespace {

HMODULE g_module = nullptr;
LONG g_objets = 0;
LONG g_verrous = 0;

// La fabrique de classe : ce que CoGetClassObject rend à LogonUI.
class CFabrique : public IClassFactory {
 public:
  CFabrique() : references_(1) {}

  IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
    if (ppv == nullptr) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_IClassFactory) {
      *ppv = static_cast<IClassFactory*>(this);
      AddRef();
      return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
  }

  IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&references_); }

  IFACEMETHODIMP_(ULONG) Release() override {
    LONG restantes = InterlockedDecrement(&references_);
    if (restantes == 0) delete this;
    return restantes;
  }

  IFACEMETHODIMP CreateInstance(IUnknown* agregat, REFIID riid, void** ppv) override {
    // L'agrégation n'est pas gérée, et c'est la réponse attendue par COM.
    vaultaire::Passage p(L"Fabrique::CreateInstance", L"interface=%ls",
                         vaultaire::NomDeLInterface(riid).c_str());
    if (agregat != nullptr) return p.Rendre(CLASS_E_NOAGGREGATION);
    InterlockedIncrement(&g_objets);
    HRESULT hr = vaultaire::CreerFournisseur(riid, ppv);
    if (FAILED(hr)) InterlockedDecrement(&g_objets);
    return p.Rendre(hr);
  }

  IFACEMETHODIMP LockServer(BOOL verrouiller) override {
    if (verrouiller) {
      InterlockedIncrement(&g_verrous);
    } else {
      InterlockedDecrement(&g_verrous);
    }
    return S_OK;
  }

 private:
  // Virtuel : détruit par « delete this » à travers un pointeur d'interface.
  virtual ~CFabrique() {}
  LONG references_;
};

// Longueur d'un GUID en texte, accolades comprises :
// {6F2A1B74-3C58-4E0A-9D21-7B4F8C0E5A93}.
const size_t kLongueurGUID = 38;

const wchar_t kRacineCOM[] = L"SOFTWARE\\Classes\\CLSID\\";
const wchar_t kRacineFournisseurs[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\";

// TexteGUID rend « {XXXXXXXX-...} », ou échoue.
//
// # Le contrôle de forme n'est pas décoratif (TO-DO 140)
//
// Ce texte devient un nom de clé, que DllRegisterServer crée et que
// DllUnregisterServer EFFACE avec tout son sous-arbre. Les chemins étaient
// composés par swprintf, format large et `%s` : sous MinGW, `%s` dans un format large
// désigne une chaîne ÉTROITE, et le GUID était lu octet par octet jusqu'au
// premier zéro de l'UTF-16 — il n'en restait que « { ». Le fournisseur
// s'inscrivait donc sous CLSID\{, où LogonUI ne le cherche pas.
//
// Si le texte avait été VIDE au lieu de « { », le retrait aurait effacé
// HKLM\SOFTWARE\Classes\CLSID\ en entier. D'où la règle : aucune écriture
// ni aucun effacement sans un GUID de 38 caractères entre accolades.
bool TexteGUID(std::wstring* guid) {
  wchar_t tampon[64] = {0};
  if (StringFromGUID2(CLSID_VaultaireProvider, tampon, 64) <= 0) return false;
  if (wcslen(tampon) != kLongueurGUID) return false;
  if (tampon[0] != L'{' || tampon[kLongueurGUID - 1] != L'}') return false;
  guid->assign(tampon);
  return true;
}

// Les chemins sont CONCATÉNÉS, pas formatés : aucune famille printf n'entre
// plus dans la composition d'un nom de clé.
std::wstring CleCOM(const std::wstring& guid) { return std::wstring(kRacineCOM) + guid; }
std::wstring CleFournisseur(const std::wstring& guid) {
  return std::wstring(kRacineFournisseurs) + guid;
}

LONG EcrireCle(HKEY racine, const wchar_t* chemin, const wchar_t* valeur, const wchar_t* donnee) {
  HKEY cle = nullptr;
  LONG r = RegCreateKeyExW(racine, chemin, 0, nullptr, REG_OPTION_NON_VOLATILE,
                           KEY_WRITE, nullptr, &cle, nullptr);
  if (r != ERROR_SUCCESS) return r;
  r = RegSetValueExW(cle, valeur, 0, REG_SZ, (const BYTE*)donnee,
                     (DWORD)((wcslen(donnee) + 1) * sizeof(wchar_t)));
  RegCloseKey(cle);
  return r;
}

// EstANous dit si la valeur par défaut d'une clé est le libellé de Vaultaire.
bool EstANous(const std::wstring& chemin) {
  wchar_t valeur[128] = {0};
  DWORD taille = sizeof(valeur) - sizeof(wchar_t);
  LONG r = RegGetValueW(HKEY_LOCAL_MACHINE, chemin.c_str(), nullptr, RRF_RT_REG_SZ,
                        nullptr, valeur, &taille);
  return r == ERROR_SUCCESS && wcscmp(valeur, VAULTAIRE_CP_NOM) == 0;
}

// RetirerInscriptionTronquee efface les clés « { » laissées par les versions
// antérieures au TO-DO 140.
//
// Elles ne gênent pas LogonUI, qui ignore un nom qui n'est pas un GUID. Mais
// elles restent dans le registre d'un poste déjà installé, et font croire à
// qui les trouve que l'inscription a encore échoué.
//
// Une clé n'est retirée que si elle porte NOTRE libellé : « { » n'est le nom
// de rien d'autre, mais on n'efface pas un sous-arbre de HKLM sur la foi d'un
// nom.
void RetirerInscriptionTronquee() {
  const std::wstring tronque = L"{";
  for (const std::wstring& chemin : {CleFournisseur(tronque), CleCOM(tronque)}) {
    if (!EstANous(chemin)) continue;
    if (RegDeleteTreeW(HKEY_LOCAL_MACHINE, chemin.c_str()) == ERROR_SUCCESS) {
      vaultaire::Journaliser(L"ancienne inscription tronquee retiree : %ls", chemin.c_str());
    }
  }
}

}  // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE module, DWORD raison, LPVOID) {
  if (raison == DLL_PROCESS_ATTACH) {
    g_module = (HMODULE)module;
    // Pas de notification de thread : la DLL est chargée dans LogonUI, qui en
    // crée beaucoup, et nous n'avons rien à y faire.
    DisableThreadLibraryCalls((HMODULE)module);
  }
  return TRUE;
}

extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
  if (ppv == nullptr) return E_POINTER;

  // Une trace au premier usage RÉEL, et une seule.
  //
  // Le journal n'était écrit qu'à l'inscription. Son absence ne distinguait donc
  // pas « pas inscrit » de « inscrit mais jamais chargé » — deux pannes
  // différentes, l'une dans le registre, l'autre dans les dépendances de la DLL,
  // et rien pour les séparer. Cette ligne est ce qui manquait : si elle est là,
  // LogonUI a trouvé la DLL, l'a chargée et a résolu ses imports.
  //
  // Ici et NON dans DllMain : DllMain tourne sous le verrou du chargeur, où
  // ouvrir un fichier est à proscrire. DllGetClassObject est appelée par COM,
  // hors de ce verrou, et sa seule exécution prouve ce qu'on veut savoir.
  // La course sur ce drapeau est bénigne, et on ne met pas de verrou pour elle :
  // le pire effet est la ligne écrite deux fois. ThreadingModel = Apartment
  // sérialise d'ailleurs l'activation, donc elle ne se produira pas.
  static bool deja_dit = false;
  if (!deja_dit) {
    deja_dit = true;
    wchar_t chemin[MAX_PATH] = {0};
    if (GetModuleFileNameW(g_module, chemin, MAX_PATH) != 0) {
      vaultaire::Journaliser(L"fournisseur charge : %ls", chemin);
    } else {
      vaultaire::Journaliser(L"fournisseur charge (chemin indisponible)");
    }
  }

  // Le témoin de trace est relu à chaque activation : LogonUI est un processus
  // neuf à chaque affichage de l'écran de connexion, mais d'autres hôtes
  // gardent la DLL chargée (vaultaire_trace.h).
  vaultaire::RelireTemoinTrace();
  vaultaire::Passage p(L"DllGetClassObject", L"interface=%ls",
                       vaultaire::NomDeLInterface(riid).c_str());

  if (rclsid != CLSID_VaultaireProvider) return p.Rendre(CLASS_E_CLASSNOTAVAILABLE);

  CFabrique* fabrique = new (std::nothrow) CFabrique();
  if (fabrique == nullptr) return p.Rendre(E_OUTOFMEMORY);
  HRESULT hr = fabrique->QueryInterface(riid, ppv);
  fabrique->Release();
  return p.Rendre(hr);
}

extern "C" HRESULT WINAPI DllCanUnloadNow() {
  return (g_objets == 0 && g_verrous == 0) ? S_OK : S_FALSE;
}

extern "C" HRESULT WINAPI DllRegisterServer() {
  std::wstring guid;
  if (!TexteGUID(&guid)) return E_FAIL;

  wchar_t chemin[MAX_PATH] = {0};
  if (GetModuleFileNameW(g_module, chemin, MAX_PATH) == 0) {
    return HRESULT_FROM_WIN32(GetLastError());
  }

  const std::wstring com = CleCOM(guid);
  const std::wstring inproc = com + L"\\InprocServer32";
  const std::wstring fournisseur = CleFournisseur(guid);

  if (EcrireCle(HKEY_LOCAL_MACHINE, com.c_str(), nullptr, VAULTAIRE_CP_NOM) != ERROR_SUCCESS) {
    return E_ACCESSDENIED;
  }
  if (EcrireCle(HKEY_LOCAL_MACHINE, inproc.c_str(), nullptr, chemin) != ERROR_SUCCESS) {
    return E_ACCESSDENIED;
  }
  // Apartment : le modèle de threads de LogonUI. « Both » laisserait COM
  // appeler le fournisseur depuis n'importe quel thread, ce que l'interface
  // n'attend pas.
  if (EcrireCle(HKEY_LOCAL_MACHINE, inproc.c_str(), L"ThreadingModel", L"Apartment") != ERROR_SUCCESS) {
    return E_ACCESSDENIED;
  }
  if (EcrireCle(HKEY_LOCAL_MACHINE, fournisseur.c_str(), nullptr, VAULTAIRE_CP_NOM) != ERROR_SUCCESS) {
    return E_ACCESSDENIED;
  }

  // Après la bonne inscription, pas avant : si elle échoue, on n'a rien retiré.
  RetirerInscriptionTronquee();

  vaultaire::Journaliser(L"fournisseur inscrit : %ls sous %ls", chemin, guid.c_str());
  return S_OK;
}

extern "C" HRESULT WINAPI DllUnregisterServer() {
  std::wstring guid;
  if (!TexteGUID(&guid)) return E_FAIL;

  RegDeleteTreeW(HKEY_LOCAL_MACHINE, CleFournisseur(guid).c_str());
  RegDeleteTreeW(HKEY_LOCAL_MACHINE, CleCOM(guid).c_str());
  RetirerInscriptionTronquee();

  vaultaire::Journaliser(L"fournisseur retiré");
  return S_OK;
}
