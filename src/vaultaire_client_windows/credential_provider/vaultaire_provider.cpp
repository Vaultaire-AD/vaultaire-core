// Le FOURNISSEUR : ce que Windows interroge pour savoir quelles tuiles afficher.
//
// Une seule tuile, la nôtre, et seulement dans les scénarios qui ont un sens
// pour Vaultaire : ouverture de session et déverrouillage. Pour le changement
// de mot de passe ou les identifiants réseau, le fournisseur se retire — une
// tuile qui apparaît là où elle ne sait rien faire n'est qu'un piège pour
// l'utilisateur.

#include "vaultaire_credential.h"
#include "vaultaire_guid.h"
#include "vaultaire_pipe.h"
#include "vaultaire_trace.h"

#include <new>

namespace vaultaire {

// Défini dans vaultaire_credential.cpp.
const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* DescriptionDesChamps();

class CVaultaireProvider : public ICredentialProvider {
 public:
  CVaultaireProvider() : references_(1), scenario_(CPUS_INVALID), credential_(nullptr) {}

  IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
    if (ppv == nullptr) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
      *ppv = static_cast<ICredentialProvider*>(this);
      AddRef();
      if (TraceActive()) Tracer(L"Fournisseur::QueryInterface %ls = accordee", NomDeLInterface(riid).c_str());
      return S_OK;
    }
    *ppv = nullptr;
    // Les refus sont tracés aussi : ils disent ce que LogonUI aurait voulu.
    if (TraceActive()) Tracer(L"Fournisseur::QueryInterface %ls = refusee", NomDeLInterface(riid).c_str());
    return E_NOINTERFACE;
  }

  IFACEMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&references_); }

  IFACEMETHODIMP_(ULONG) Release() override {
    LONG restantes = InterlockedDecrement(&references_);
    if (restantes == 0) delete this;
    return restantes;
  }

  // Une ligne par CHANGEMENT de scénario, pas par appel.
  //
  // LogonUI appelle SetUsageScenario à chaque reconstruction de son interface —
  // une frappe au clavier, un retour d'écran de veille. Journaliser à chaque
  // fois ferait croître sans borne un fichier de C:\ProgramData, que rien ne
  // fait tourner. Avant ce point, la DLL n'écrivait que sur action délibérée.
  void JournaliserScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, const wchar_t* verdict) {
    if (scenario == journalise_) return;
    journalise_ = scenario;
    Journaliser(L"scenario %u %ls", (unsigned)scenario, verdict);
  }

  // SetUsageScenario : Windows annonce POURQUOI il demande des identifiants.
  IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
                                  DWORD drapeaux) override {
    // Le témoin est relu ICI : c'est le premier appel de chaque affichage de
    // l'écran de connexion, donc le moment où poser ou retirer le fichier doit
    // prendre effet.
    RelireTemoinTrace();
    Passage p(L"Fournisseur::SetUsageScenario", L"scenario=%u drapeaux=0x%08lx",
              (unsigned)scenario, (unsigned long)drapeaux);
    switch (scenario) {
      case CPUS_LOGON:
      case CPUS_UNLOCK_WORKSTATION:
        break;
      case CPUS_CHANGE_PASSWORD:
        // Changer son mot de passe Vaultaire se fait dans le portail : le core
        // en est la source. Proposer la tuile ici laisserait croire qu'on peut
        // le changer depuis l'écran de connexion, ce qui ne changerait que le
        // compte local — donc rien, au prochain provisionnement.
        JournaliserScenario(scenario, L"refuse (le mot de passe se change dans le portail)");
        return p.Rendre(E_NOTIMPL);
      default:
        // Journalisé, parce qu'un refus ici est INDISCERNABLE d'une DLL non
        // chargée : dans les deux cas la tuile n'apparaît pas. La ligne dit
        // lequel des deux on regarde.
        JournaliserScenario(scenario, L"refuse (pas de tuile dans ce contexte)");
        return p.Rendre(E_NOTIMPL);
    }
    JournaliserScenario(scenario, L"accepte (la tuile doit apparaitre)");

    scenario_ = scenario;
    if (credential_ != nullptr) {
      credential_->Release();
      credential_ = nullptr;
    }
    credential_ = new (std::nothrow) CVaultaireCredential();
    if (credential_ == nullptr) return p.Rendre(E_OUTOFMEMORY);
    return p.Rendre(credential_->Initialiser(scenario));
  }

  // SetSerialization : Windows propose des identifiants déjà sérialisés
  // (ouverture de session à distance, par exemple). Non géré en V1.
  IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override {
    Passage p(L"Fournisseur::SetSerialization");
    return p.Rendre(E_NOTIMPL);
  }

  // Advise / UnAdvise : le fournisseur ne provoque jamais de rafraîchissement
  // des tuiles — il n'a rien qui change tout seul.
  IFACEMETHODIMP Advise(ICredentialProviderEvents*, UINT_PTR) override {
    Passage p(L"Fournisseur::Advise");
    return p.Rendre(E_NOTIMPL);
  }
  IFACEMETHODIMP UnAdvise() override {
    Passage p(L"Fournisseur::UnAdvise");
    return p.Rendre(E_NOTIMPL);
  }

  IFACEMETHODIMP GetFieldDescriptorCount(DWORD* nombre) override {
    Passage p(L"Fournisseur::GetFieldDescriptorCount");
    if (nombre == nullptr) return p.Rendre(E_INVALIDARG);
    *nombre = kNombreDeChamps;
    return p.Rendre(S_OK);
  }

  IFACEMETHODIMP GetFieldDescriptorAt(DWORD rang,
                                      CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** description) override {
    Passage p(L"Fournisseur::GetFieldDescriptorAt", L"rang=%lu", (unsigned long)rang);
    if (rang >= kNombreDeChamps || description == nullptr) return p.Rendre(E_INVALIDARG);

    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& source = DescriptionDesChamps()[rang];
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* copie =
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(*copie));
    if (copie == nullptr) return p.Rendre(E_OUTOFMEMORY);

    *copie = source;
    // Le LIBELLÉ est recopié : Windows libère la description avec
    // CoTaskMemFree, et lui passer un pointeur vers une constante du module
    // ferait planter LogonUI — donc disparaître l'écran de connexion.
    const size_t octets = (wcslen(source.pszLabel) + 1) * sizeof(wchar_t);
    copie->pszLabel = (wchar_t*)CoTaskMemAlloc(octets);
    if (copie->pszLabel == nullptr) {
      CoTaskMemFree(copie);
      return p.Rendre(E_OUTOFMEMORY);
    }
    CopyMemory(copie->pszLabel, source.pszLabel, octets);

    *description = copie;
    return p.Rendre(S_OK);
  }

  IFACEMETHODIMP GetCredentialCount(DWORD* nombre, DWORD* par_defaut,
                                    BOOL* auto_ouvrir) override {
    Passage p(L"Fournisseur::GetCredentialCount");
    if (nombre == nullptr || par_defaut == nullptr || auto_ouvrir == nullptr) {
      return p.Rendre(E_INVALIDARG);
    }
    *nombre = 1;
    *par_defaut = 0;
    // JAMAIS d'ouverture automatique : il n'y a pas d'identifiants à rejouer,
    // et une tuile qui se soumet seule ferait boucler l'écran de connexion.
    *auto_ouvrir = FALSE;
    return p.Rendre(S_OK);
  }

  IFACEMETHODIMP GetCredentialAt(DWORD rang, ICredentialProviderCredential** credential) override {
    Passage p(L"Fournisseur::GetCredentialAt", L"rang=%lu", (unsigned long)rang);
    if (rang != 0 || credential == nullptr || credential_ == nullptr) return p.Rendre(E_INVALIDARG);
    return p.Rendre(
        credential_->QueryInterface(IID_ICredentialProviderCredential, (void**)credential));
  }

 private:
  // Dernier scénario journalisé. Initialisé à une valeur qu'aucun scénario ne
  // prend, pour que le premier appel écrive toujours sa ligne.
  CREDENTIAL_PROVIDER_USAGE_SCENARIO journalise_ =
      static_cast<CREDENTIAL_PROVIDER_USAGE_SCENARIO>(0xFFFFFFFF);

  // Virtuel : détruit par « delete this » à travers un pointeur d'interface.
  virtual ~CVaultaireProvider() {
    if (credential_ != nullptr) credential_->Release();
  }

  LONG references_;
  CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
  CVaultaireCredential* credential_;
};

// CreerFournisseur est appelée par la fabrique de classe (vaultaire_dll.cpp).
HRESULT CreerFournisseur(REFIID riid, void** ppv) {
  CVaultaireProvider* fournisseur = new (std::nothrow) CVaultaireProvider();
  if (fournisseur == nullptr) return E_OUTOFMEMORY;
  HRESULT hr = fournisseur->QueryInterface(riid, ppv);
  fournisseur->Release();
  return hr;
}

}  // namespace vaultaire
