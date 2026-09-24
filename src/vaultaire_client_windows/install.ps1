# =====================================================================
# install.ps1 — installer l'agent Vaultaire sur un poste Windows
# =====================================================================
#
# Installation MANUELLE et assistée : rien ne s'installe tout seul, rien n'est
# deviné. Le script pose les questions dont il a besoin, écrit la configuration,
# pose les droits, et n'enregistre le Credential Provider que si on le lui dit.
#
# À lancer depuis une invite PowerShell ADMINISTRATEUR, dans le dossier
# décompressé de l'archive :
#
#     .\install.ps1
#
# Tout se désinstalle avec .\uninstall.ps1.

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    # Répertoire d'état. Le même que celui compilé dans l'agent.
    [string]$Racine = "C:\ProgramData\Vaultaire",
    # Dossier d'identité fourni par le core (client_software.yaml + private_key.pem).
    [string]$Identite = "",
    # Cores joignables : « 10.0.0.10:6666,10.0.0.11:6666 ».
    [string]$Cores = "",
    # Ne pose aucune question : pour une réinstallation scriptée.
    [switch]$SansQuestion
)

$ErrorActionPreference = "Stop"

$Bin = Join-Path $Racine "bin"
$Cles = Join-Path $Racine "keys"
$Journaux = Join-Path $Racine "logs"
$Config = Join-Path $Racine "client_conf.json"
$Service = "VaultaireAgent"
$Source = $PSScriptRoot

function Titre($texte) { Write-Host "`n=== $texte ===" -ForegroundColor Cyan }
function Info($texte)  { Write-Host "    $texte" }
function Erreur($texte) { Write-Host "[x] $texte" -ForegroundColor Red; exit 1 }

function Demander($question, $defaut) {
    if ($SansQuestion) { return $defaut }
    $invite = if ($defaut) { "$question [$defaut]" } else { $question }
    $reponse = Read-Host $invite
    if ([string]::IsNullOrWhiteSpace($reponse)) { return $defaut }
    return $reponse.Trim()
}

function DemanderOuiNon($question, $defautOui) {
    $defaut = if ($defautOui) { "O" } else { "N" }
    $reponse = Demander "$question (O/N)" $defaut
    return $reponse -match '^[oOyY]'
}

# EcrireTexte écrit un fichier en UTF-8 SANS marque d'ordre des octets (BOM).
#
# # Pourquoi pas Set-Content -Encoding UTF8
#
# Dans Windows PowerShell 5.1 — celui livré avec Windows, donc celui qui lancera
# ce script — « -Encoding UTF8 » écrit un BOM (EF BB BF) en tête de fichier. Or
# la norme JSON ne l'autorise pas : le décodeur de l'agent refuse le document et
# se plaint d'un « caractère invalide 'ï' », ce qui n'évoque rien pour personne.
# L'agent ne lisait donc jamais sa configuration (recette du 24/09).
#
# « > » et « Out-File » sans option sont pires encore : ils écrivent en UTF-16LE,
# illisible pour tout ce qui attend du texte.
#
# WriteAllText avec un UTF8Encoding($false) est le seul moyen sûr d'obtenir de
# l'UTF-8 nu, identique sur PowerShell 5.1 et 7.
function EcrireTexte($chemin, $texte) {
    $utf8SansBOM = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($chemin, $texte, $utf8SansBOM)
}

Titre "Agent Vaultaire pour Windows"
Info "Racine d'installation : $Racine"

# --- 1. Les binaires -------------------------------------------------------
foreach ($fichier in @("vaultaire_client_windows.exe", "vaultaire_login.exe")) {
    if (-not (Test-Path (Join-Path $Source $fichier))) {
        Erreur "$fichier introuvable à côté de ce script : archive incomplète."
    }
}

New-Item -ItemType Directory -Force -Path $Bin, $Cles, $Journaux | Out-Null
Copy-Item (Join-Path $Source "vaultaire_client_windows.exe") $Bin -Force
Copy-Item (Join-Path $Source "vaultaire_login.exe") $Bin -Force
Info "binaires copiés dans $Bin"

# --- 2. Les droits, AVANT d'y écrire quoi que ce soit -----------------------
#
# La clé privée de la machine et son identité vivent ici. Le répertoire est
# fermé à tout le monde sauf SYSTEM et les administrateurs — un utilisateur du
# poste qui lirait la clé privée pourrait se faire passer pour la machine.
Titre "Droits sur $Racine"
$acl = Get-Acl $Racine
$acl.SetAccessRuleProtection($true, $false)   # plus aucun héritage
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
foreach ($compte in @("SYSTEM", "BUILTIN\Administrateurs", "BUILTIN\Administrators")) {
    try {
        $regle = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $compte, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($regle)
    } catch {
        # Le nom du groupe des administrateurs est TRADUIT : on essaie les deux
        # orthographes et on garde celle qui existe sur cette machine.
    }
}
Set-Acl -Path $Racine -AclObject $acl
Info "accès restreint à SYSTEM et aux administrateurs"

# --- 3. L'identité de la machine -------------------------------------------
#
# Elle est CRÉÉE SUR LE CORE, jamais ici : `vlt create -c <nom>` produit un
# dossier clientsoftware/<id>/ contenant client_software.yaml et
# private_key.pem. C'est ce dossier qu'on apporte sur le poste (clé USB,
# partage, scp). Un agent ne s'enrôle pas seul : seuls les SERVICES du cluster
# le font, avec une clé d'enrôlement.
Titre "Identité de la machine"
if (-not $Identite) {
    Info "Sur le core : vlt create -c <nom-du-poste>"
    Info "Puis copiez le dossier clientsoftware\<id>\ sur ce poste."
    $Identite = Demander "Chemin du dossier d'identité" ""
}
if (-not $Identite -or -not (Test-Path $Identite)) {
    Erreur "Dossier d'identité introuvable : sans lui, l'agent ne peut pas s'authentifier."
}
foreach ($fichier in @("client_software.yaml", "private_key.pem")) {
    $chemin = Join-Path $Identite $fichier
    if (-not (Test-Path $chemin)) { Erreur "$fichier absent de $Identite" }
}
Copy-Item (Join-Path $Identite "client_software.yaml") (Join-Path $Racine "client_software.yaml") -Force
Copy-Item (Join-Path $Identite "private_key.pem") (Join-Path $Cles "private_key.pem") -Force
foreach ($facultatif in @("public.pem", "core_key_fingerprint")) {
    $chemin = Join-Path $Identite $facultatif
    if (Test-Path $chemin) { Copy-Item $chemin (Join-Path $Cles $facultatif) -Force }
}
Info "identité en place"

# L'empreinte de la clé du core : facultative, mais c'est elle qui empêche un
# faux core de se faire accepter au premier contact. Sans elle, l'agent fait
# confiance à ce qui répond la première fois.
$empreinte = Join-Path $Cles "core_key_fingerprint"
if (-not (Test-Path $empreinte)) {
    Info "Aucune empreinte de core fournie : la première connexion fera confiance"
    Info "au serveur qui répond (sur le core : vlt certificate fingerprint)."
    $valeur = Demander "Empreinte du core (SHA256:... , vide pour passer)" ""
    if ($valeur) { EcrireTexte $empreinte ($valeur.Trim() + "`n") }
}

# --- 4. La configuration ---------------------------------------------------
Titre "Cores joignables"
if (-not $Cores) {
    Info "Adresses des cores ou proxies, séparées par des virgules."
    Info "L'agent apprendra les autres tout seul (trame 04_04) et les persistera."
    $Cores = Demander "Cores (ip:port)" "127.0.0.1:6666"
}

$serveurs = @()
foreach ($adresse in $Cores.Split(",")) {
    $adresse = $adresse.Trim()
    if (-not $adresse) { continue }
    $morceaux = $adresse.Split(":")
    $ip = $morceaux[0]
    $port = if ($morceaux.Count -gt 1) { [int]$morceaux[1] } else { 6666 }
    if ($port -lt 1 -or $port -gt 65535) { Erreur "port invalide dans « $adresse »" }
    $serveurs += [pscustomobject]@{ ip = $ip; port = $port }
}
if ($serveurs.Count -eq 0) { Erreur "aucun core déclaré : l'agent ne saurait à qui parler." }

# « servers » n'est jamais réécrite par l'agent : c'est le dernier recours,
# celui qui reste quand tout ce qui a été appris est faux ou éteint.
$contenu = [ordered]@{ servers = $serveurs }
EcrireTexte $Config (($contenu | ConvertTo-Json -Depth 4) + "`n")
Info "configuration écrite : $Config"

# --- 5. Le service ---------------------------------------------------------
Titre "Service Windows"
if (DemanderOuiNon "Installer le service $Service" $true) {
    if (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
        Info "service déjà présent : arrêt et mise à jour"
        Stop-Service $Service -Force -ErrorAction SilentlyContinue
        sc.exe delete $Service | Out-Null
        Start-Sleep -Seconds 2
    }
    $commande = "`"$Bin\vaultaire_client_windows.exe`" -racine `"$Racine`""
    # LocalSystem : l'agent lit la clé privée de la machine, crée des comptes
    # locaux et sert un tube réservé à SYSTEM. Aucun compte moindre ne le peut.
    sc.exe create $Service binPath= $commande start= auto obj= LocalSystem DisplayName= "Agent Vaultaire" | Out-Null
    sc.exe description $Service "Authentifie les utilisateurs du domaine Vaultaire et maintient le tunnel vers le core." | Out-Null
    # Redémarrage automatique : sans agent, plus personne ne se connecte.
    sc.exe failure $Service reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    Start-Service $Service
    Info "service démarré"
} else {
    Info "service non installé — lancez l'agent à la main :"
    Info "  $Bin\vaultaire_client_windows.exe -console"
}

# --- 5 bis. La politique de mot de passe locale ----------------------------
#
# Windows crée le compte local avec LE MOT DE PASSE DU DOMAINE, et il n'y a pas
# le choix : c'est celui que la personne tape à l'écran de connexion, et c'est
# Windows qui le vérifie contre le compte local. En poser un autre rendrait la
# connexion impossible.
#
# Conséquence : si la politique locale du poste est plus stricte que celle du
# domaine, NetUserAdd refuse le compte avec le code 2245 — et rien ne se passe
# (recette du 24/09). Le poste refuse un mot de passe que le core vient de
# valider.
#
# On PROPOSE de l'aligner, on ne le fait pas d'office : c'est une politique de
# sécurité du poste, et l'assouplir sans le dire serait exactement le genre de
# décision qu'un installeur n'a pas à prendre seul.
Titre "Politique de mot de passe locale"

function PolitiqueLocale {
    $sortie = & net accounts 2>$null
    $longueur = ($sortie | Select-String -Pattern "^(Minimum password length|Longueur minimale du mot de passe)" |
                 ForEach-Object { ($_ -split ":")[-1].Trim() })
    $historique = ($sortie | Select-String -Pattern "^(Length of password history|Longueur de l.historique)" |
                 ForEach-Object { ($_ -split ":")[-1].Trim() })
    return @{ Longueur = $longueur; Historique = $historique }
}

$politique = PolitiqueLocale
Info "longueur minimale : $($politique.Longueur)"
Info "historique        : $($politique.Historique)"
Info ""
Info "Si ces règles sont plus strictes que celles de votre domaine Vaultaire, la"
Info "création du compte local échouera avec « code 2245 » et personne ne pourra"
Info "ouvrir de session — le mot de passe local EST celui du domaine."

if (DemanderOuiNon "Aligner la politique locale (longueur 0, aucun historique, complexite desactivee)" $false) {
    # `net accounts` couvre la longueur et l'historique ; la COMPLEXITÉ n'y est
    # pas exposée et demande secedit, qui passe par un export/import de la
    # stratégie de sécurité locale.
    & net accounts /minpwlen:0 /uniquepw:0 | Out-Null

    $export = Join-Path $env:TEMP "vaultaire-secpol.cfg"
    $base   = Join-Path $env:TEMP "vaultaire-secpol.sdb"
    & secedit /export /cfg $export /areas SECURITYPOLICY | Out-Null
    if (Test-Path $export) {
        $cfg = Get-Content $export
        $cfg = $cfg -replace "^PasswordComplexity\s*=.*", "PasswordComplexity = 0"
        $cfg = $cfg -replace "^MinimumPasswordLength\s*=.*", "MinimumPasswordLength = 0"
        $cfg = $cfg -replace "^PasswordHistorySize\s*=.*", "PasswordHistorySize = 0"

        # UTF-16, et c'est LE cas où c'est correct : secedit produit et attend
        # de l'Unicode. Le réécrire en UTF-8 — ce que fait EcrireTexte pour tout
        # le reste — le rendrait illisible pour secedit. La règle n'est pas
        # « toujours de l'UTF-8 », c'est « l'encodage que le lecteur attend ».
        Set-Content -Path $export -Value $cfg -Encoding Unicode

        & secedit /configure /db $base /cfg $export /areas SECURITYPOLICY | Out-Null
        Remove-Item $export, $base -Force -ErrorAction SilentlyContinue
        Info "politique locale alignée (complexité désactivée)"
    } else {
        Info "secedit n'a rien exporté : la complexité n'a PAS été modifiée."
        Info "À faire à la main dans secpol.msc → Stratégies de mot de passe."
    }

    $politique = PolitiqueLocale
    Info "longueur minimale : $($politique.Longueur)"
    Write-Host "`n    ⚠ Cette machine accepte désormais des mots de passe locaux faibles." -ForegroundColor Yellow
    Write-Host "      La robustesse est alors celle de votre politique de DOMAINE, qui est" -ForegroundColor Yellow
    Write-Host "      ce qui protège réellement le compte." -ForegroundColor Yellow
} else {
    Info "politique inchangée."
    Info "Si « code 2245 » apparaît à la connexion, c'est elle : secpol.msc, ou"
    Info "relancez ce script."
}

# Machine jointe à un Active Directory : une stratégie de DOMAINE écrase la
# politique locale à chaque actualisation. Il faut alors la régler côté AD.

# --- 6. Le Credential Provider ---------------------------------------------
Titre "Écran de connexion"
$dll = Join-Path $Source "VaultaireCredentialProvider.dll"
if (-not (Test-Path $dll)) {
    Info "DLL absente de l'archive : l'écran de connexion Windows n'est pas modifié."
    Info "L'agent et vaultaire_login.exe fonctionnent quand même."
} elseif (DemanderOuiNon "Enregistrer le Credential Provider (tuile Vaultaire a l'ecran de connexion)" $false) {
    Copy-Item $dll $Bin -Force
    & regsvr32.exe /s (Join-Path $Bin "VaultaireCredentialProvider.dll")
    if ($LASTEXITCODE -ne 0) { Erreur "regsvr32 a échoué (code $LASTEXITCODE)" }
    Info "tuile Vaultaire enregistrée — elle apparaîtra au prochain verrouillage"
    Write-Host "`n    ⚠ Gardez une session administrateur locale OUVERTE le temps de vérifier" -ForegroundColor Yellow
    Write-Host "      que la connexion fonctionne : un fournisseur défaillant se retire avec" -ForegroundColor Yellow
    Write-Host "      .\uninstall.ps1 -CredentialProviderSeulement, depuis cette session." -ForegroundColor Yellow
} else {
    Info "tuile non enregistrée (l'agent tourne, l'écran de connexion est inchangé)"
}

# --- 7. Vérification -------------------------------------------------------
Titre "Vérification"
Info "état de l'agent :"
& (Join-Path $Bin "vaultaire_login.exe") -etat
Write-Host ""
Info "essai complet    : $Bin\vaultaire_login.exe -u utilisateur@domaine"
Info "journal de l'agent : $Journaux\vaultaire_client_windows.log"
Info "côté core          : vlt status -c"
