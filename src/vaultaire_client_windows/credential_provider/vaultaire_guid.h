// L'identifiant COM du fournisseur.
//
// Windows range les Credential Providers par CLSID sous
// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers.
// Ce GUID est donc l'IDENTITÉ de Vaultaire à l'écran de connexion : il est tiré
// une fois et ne change plus. Le changer ferait cohabiter deux tuiles après une
// mise à jour, l'ancienne pointant sur une DLL désinstallée.

#pragma once

#include <initguid.h>

// {6F2A1B74-3C58-4E0A-9D21-7B4F8C0E5A93}
DEFINE_GUID(CLSID_VaultaireProvider,
            0x6f2a1b74, 0x3c58, 0x4e0a, 0x9d, 0x21, 0x7b, 0x4f, 0x8c, 0x0e, 0x5a, 0x93);

// Les rôles de champ que LogonUI reconnaît pour un fournisseur « V2 » (TO-DO 157).
//
// Recopiés de shlguid.h du Windows SDK — MinGW les porte aussi, mais seulement
// dans shlguid.h, et l'inclure ici définirait des dizaines d'autres GUID dans
// la DLL. Le faux LogonUI compare ces valeurs à celles de shlguid.h : une faute
// de frappe ne passerait pas la fabrication.
//
//   LOGO   l'image du fournisseur dans les « Options de connexion » ;
//   LABEL  son nom, en info-bulle de cette image.
DEFINE_GUID(VAULTAIRE_CPFG_LOGO,
            0x2d837775, 0xf6cd, 0x464e, 0xa7, 0x45, 0x48, 0x2f, 0xd0, 0xb4, 0x74, 0x93);
DEFINE_GUID(VAULTAIRE_CPFG_LABEL,
            0x286bbff3, 0xbad4, 0x438f, 0xb0, 0x07, 0x79, 0xb7, 0x26, 0x7c, 0x3d, 0x48);

// Le libellé affiché dans le registre, pour qu'un administrateur qui liste les
// fournisseurs sache lequel est celui-ci.
#define VAULTAIRE_CP_NOM L"Vaultaire Credential Provider"
