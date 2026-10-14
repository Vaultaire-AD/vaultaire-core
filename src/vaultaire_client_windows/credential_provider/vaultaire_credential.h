// La TUILE de l'écran de connexion : ses champs, et ce qui se passe au clic.

#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <string>

namespace vaultaire {

// Le compte des objets vivants du module (vaultaire_dll.cpp) : chaque objet
// COM l'incrémente dans son constructeur et le décrémente dans son
// destructeur. C'est ce que lit DllCanUnloadNow.
void ObjetCree();
void ObjetDetruit();

// Les champs de la tuile, dans l'ordre où Windows les affiche.
//
// L'ordre EST l'interface : Winlogon les identifie par leur rang, et insérer un
// champ au milieu décale tout ce qui suit — le mot de passe se retrouverait lu
// comme un nom d'utilisateur.
enum Champ {
  kChampTitre = 0,      // « Vaultaire », grand texte
  kChampUtilisateur,    // saisie : alice@domaine.fr
  kChampMotDePasse,     // saisie masquée
  // Second facteur (TO-DO 95). Saisie masquée elle aussi : un code TOTP reste
  // valide jusqu'à 90 secondes, assez pour que quelqu'un qui regarde l'écran
  // s'en serve. L'ordre place ce champ APRÈS le mot de passe — et avant le
  // bouton — parce que c'est l'ordre dans lequel on le saisit.
  kChampCode,
  kChampValider,        // bouton
  kChampMessage,        // petit texte : état de l'agent, motif d'un refus
  // Ajoutés par le TO-DO 157, À LA FIN pour ne décaler aucun rang existant.
  // Ce sont les deux champs que porte tout fournisseur « V2 » de Microsoft
  // (SampleV2CredentialProvider) : LogonUI les retrouve par leur rôle
  // (guidFieldType), pas par leur rang.
  kChampImage,          // image de la tuile, rôle CPFG_CREDENTIAL_PROVIDER_LOGO
  kChampLibelle,        // nom du fournisseur, rôle CPFG_CREDENTIAL_PROVIDER_LABEL, masqué
  kNombreDeChamps,
};

// La variante d'essai qui reste du TO-DO 157 — TO-DO 179.
//
// Le 157 avait rendu la DLL « V2 » à l'aveugle (ICredentialProviderCredential2,
// ICredentialProviderSetUserArray), avec trois variantes pour en chercher la
// cause sur un poste. La recette du 12/10 l'a trouvée : c'est le V2. Avec lui,
// les tuiles restent vides ou l'interface Vaultaire est masquée ; poser
// ModeV1 = 1 rétablit aussitôt l'écran, et la connexion passe.
//
// Le V1 est donc le comportement PAR DÉFAUT, sans rien à poser. TuileParDefaut
// et SansImage sont retirées : elles ne ramenaient rien, et l'image et
// l'absence de tuile par défaut sont celles qui marchent en V1.
//
// Reste une valeur, pour un essai seulement :
//
//   ModeV2 = 1  (DWORD, HKLM\SOFTWARE\Vaultaire\CredentialProvider)
//               la tuile se dit ICredentialProviderCredential2 et le
//               fournisseur accepte ICredentialProviderSetUserArray — le
//               comportement du 157, celui qui casse l'écran.
//
// Elle ne sert qu'à chercher POURQUOI le V2 casse l'écran, si l'énumération
// des comptes devient un jour utile (TO-DO 179, point 4). Lue à la création du
// fournisseur ; active, elle est écrite au journal de la DLL.
struct Variantes {
  bool mode_v2 = false;
};
Variantes LireVariantes();

class CVaultaireCredential : public ICredentialProviderCredential2 {
 public:
  CVaultaireCredential();

  HRESULT Initialiser(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, const Variantes& variantes);

  // IUnknown
  IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
  IFACEMETHODIMP_(ULONG) AddRef() override;
  IFACEMETHODIMP_(ULONG) Release() override;

  // ICredentialProviderCredential
  IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* evenements) override;
  IFACEMETHODIMP UnAdvise() override;
  IFACEMETHODIMP SetSelected(BOOL* auto_ouvrir) override;
  IFACEMETHODIMP SetDeselected() override;
  IFACEMETHODIMP GetFieldState(DWORD champ,
                               CREDENTIAL_PROVIDER_FIELD_STATE* etat,
                               CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interaction) override;
  IFACEMETHODIMP GetStringValue(DWORD champ, wchar_t** valeur) override;
  IFACEMETHODIMP GetBitmapValue(DWORD champ, HBITMAP* image) override;
  IFACEMETHODIMP GetCheckboxValue(DWORD champ, BOOL* coche, wchar_t** libelle) override;
  IFACEMETHODIMP GetSubmitButtonValue(DWORD champ, DWORD* champ_adjacent) override;
  IFACEMETHODIMP GetComboBoxValueCount(DWORD champ, DWORD* nombre, DWORD* selection) override;
  IFACEMETHODIMP GetComboBoxValueAt(DWORD champ, DWORD element, wchar_t** valeur) override;
  IFACEMETHODIMP SetStringValue(DWORD champ, const wchar_t* valeur) override;
  IFACEMETHODIMP SetCheckboxValue(DWORD champ, BOOL coche) override;
  IFACEMETHODIMP SetComboBoxSelectedValue(DWORD champ, DWORD element) override;
  IFACEMETHODIMP CommandLinkClicked(DWORD champ) override;
  IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* reponse,
                                  CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialisation,
                                  wchar_t** texte_erreur,
                                  CREDENTIAL_PROVIDER_STATUS_ICON* icone) override;
  IFACEMETHODIMP ReportResult(NTSTATUS etat, NTSTATUS sous_etat,
                              wchar_t** texte_erreur,
                              CREDENTIAL_PROVIDER_STATUS_ICON* icone) override;

  // ICredentialProviderCredential2
  IFACEMETHODIMP GetUserSid(wchar_t** sid) override;

 private:
  // Destructeur VIRTUEL : l'objet est détruit par « delete this » depuis
  // Release(), à travers un pointeur d'interface. Sans virtual, seul le
  // destructeur de base tournerait — le mot de passe ne serait pas effacé.
  virtual ~CVaultaireCredential();
  void EffacerMotDePasse();
  // Même traitement que le mot de passe : un code reste valide jusqu'à 90
  // secondes, il ne doit pas traîner dans la mémoire de LogonUI.
  void EffacerCode();

  // Le corps de GetStringValue et de GetSerialization. Séparés des méthodes
  // COM pour que celles-ci n'aient qu'UN retour : c'est lui que la trace écrit
  // (vaultaire_trace.h), et un corps à dix sorties en oublierait une.
  HRESULT ValeurDuChamp(DWORD champ, wchar_t** valeur);
  HRESULT Soumettre(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* reponse,
                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialisation,
                    wchar_t** texte_erreur, CREDENTIAL_PROVIDER_STATUS_ICON* icone);

  LONG references_;
  CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
  Variantes variantes_;
  ICredentialProviderCredentialEvents* evenements_;

  std::wstring utilisateur_;
  std::wstring mot_de_passe_;
  std::wstring code_;
  std::wstring message_;
};

}  // namespace vaultaire
