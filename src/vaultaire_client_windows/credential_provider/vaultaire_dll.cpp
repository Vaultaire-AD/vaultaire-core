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

#include <windows.h>
#include <credentialprovider.h>
#include <new>
#include <stdio.h>

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
    if (agregat != nullptr) return CLASS_E_NOAGGREGATION;
    InterlockedIncrement(&g_objets);
    HRESULT hr = vaultaire::CreerFournisseur(riid, ppv);
    if (FAILED(hr)) InterlockedDecrement(&g_objets);
    return hr;
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

// TexteGUID rend « {XXXXXXXX-...} ».
bool TexteGUID(wchar_t* tampon, size_t taille) {
  return StringFromGUID2(CLSID_VaultaireProvider, tampon, (int)taille) > 0;
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
  if (rclsid != CLSID_VaultaireProvider) return CLASS_E_CLASSNOTAVAILABLE;

  CFabrique* fabrique = new (std::nothrow) CFabrique();
  if (fabrique == nullptr) return E_OUTOFMEMORY;
  HRESULT hr = fabrique->QueryInterface(riid, ppv);
  fabrique->Release();
  return hr;
}

extern "C" HRESULT WINAPI DllCanUnloadNow() {
  return (g_objets == 0 && g_verrous == 0) ? S_OK : S_FALSE;
}

extern "C" HRESULT WINAPI DllRegisterServer() {
  wchar_t guid[64] = {0};
  if (!TexteGUID(guid, 64)) return E_FAIL;

  wchar_t chemin[MAX_PATH] = {0};
  if (GetModuleFileNameW(g_module, chemin, MAX_PATH) == 0) {
    return HRESULT_FROM_WIN32(GetLastError());
  }

  wchar_t cle[512];

  swprintf(cle, 512, L"SOFTWARE\\Classes\\CLSID\\%s", guid);
  if (EcrireCle(HKEY_LOCAL_MACHINE, cle, nullptr, VAULTAIRE_CP_NOM) != ERROR_SUCCESS) {
    return E_ACCESSDENIED;
  }

  swprintf(cle, 512, L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", guid);
  if (EcrireCle(HKEY_LOCAL_MACHINE, cle, nullptr, chemin) != ERROR_SUCCESS) {
    return E_ACCESSDENIED;
  }
  // Apartment : le modèle de threads de LogonUI. « Both » laisserait COM
  // appeler le fournisseur depuis n'importe quel thread, ce que l'interface
  // n'attend pas.
  if (EcrireCle(HKEY_LOCAL_MACHINE, cle, L"ThreadingModel", L"Apartment") != ERROR_SUCCESS) {
    return E_ACCESSDENIED;
  }

  swprintf(cle, 512,
           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\"
           L"Credential Providers\\%s", guid);
  if (EcrireCle(HKEY_LOCAL_MACHINE, cle, nullptr, VAULTAIRE_CP_NOM) != ERROR_SUCCESS) {
    return E_ACCESSDENIED;
  }

  vaultaire::Journaliser(L"fournisseur inscrit : %s", chemin);
  return S_OK;
}

extern "C" HRESULT WINAPI DllUnregisterServer() {
  wchar_t guid[64] = {0};
  if (!TexteGUID(guid, 64)) return E_FAIL;

  wchar_t cle[512];

  swprintf(cle, 512,
           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\"
           L"Credential Providers\\%s", guid);
  RegDeleteTreeW(HKEY_LOCAL_MACHINE, cle);

  swprintf(cle, 512, L"SOFTWARE\\Classes\\CLSID\\%s", guid);
  RegDeleteTreeW(HKEY_LOCAL_MACHINE, cle);

  vaultaire::Journaliser(L"fournisseur retiré");
  return S_OK;
}
