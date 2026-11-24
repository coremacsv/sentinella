# =====================================================================
#  SENTINELLA - Sistema
#  Funzioni che leggono dal PC informazioni usate da piu' controlli:
#  firme digitali, programmi installati, dischi, e la memoria delle
#  conferme date dall'utente.
# =====================================================================

# Solo queste sono proprieta' aggiunte da PowerShell: un filtro su "PS*" nasconderebbe
# anche un programma in avvio che si chiama, per esempio, "PSUpdater".
$proprietaPS = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
$reg = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
$chiaviAvvio = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$cartelleEsecuzioneAutomatica = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                                  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")

# Archivio di programmi legittimi noti che non firmano digitalmente i propri
# eseguibili Windows. Elenco piccolo di proposito: solo voci verificate una
# per una, non nomi indovinati.
$componentiNoti = [ordered]@{
    'flyctl' = "Strumento a riga di comando ufficiale di Fly.io (fly.io), usato per gestire applicazioni ospitate su quel servizio. Non firma i binari Windows."
    'Equalizer APO' = "Equalizzatore audio open source (sourceforge.net/projects/equalizerapo). I suoi eseguibili non sono mai stati firmati digitalmente."
}
function ComponenteNoto($nome) {
    foreach ($chiave in $componentiNoti.Keys) {
        if ($nome -like "*$chiave*") { return $componentiNoti[$chiave] }
    }
    return $null
}

$cacheFirme = @{}
function FirmaDi($p) {
    $x = EstraiEseguibile $p
    if (-not $x -or -not (Test-Path -LiteralPath $x -PathType Leaf)) { return $null }
    if ($script:cacheFirme.ContainsKey($x)) { return $script:cacheFirme[$x] }
    $f = Get-AuthenticodeSignature -LiteralPath $x -ErrorAction SilentlyContinue
    $script:cacheFirme[$x] = $f
    return $f
}
# I malware comuni non sono firmati digitalmente. Senza questo controllo
# lo strumento accusa Windows Defender stesso, che vive sotto ProgramData.
function FirmaValida($p) {
    $f = FirmaDi $p
    return ($f -and $f.Status -eq 'Valid')
}
# L'impronta SHA256 permette di verificare un file sospetto su VirusTotal
# senza caricarlo: si incolla il codice nella casella di ricerca.
$cacheImpronte = @{}
function Impronta($p) {
    $x = EstraiEseguibile $p
    if (-not $x -or -not (Test-Path -LiteralPath $x -PathType Leaf)) { return '' }
    if ($script:cacheImpronte.ContainsKey($x)) { return $script:cacheImpronte[$x] }
    $h = ''
    try { $h = (Get-FileHash -LiteralPath $x -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
    $script:cacheImpronte[$x] = $h
    return $h
}
function NomeFirmatario($p) {
    $f = FirmaDi $p
    if ($f -and $f.SignerCertificate) {
        $s = $f.SignerCertificate.Subject
        # Il nome puo' essere tra virgolette e contenere virgole
        # (es. CN="Corsair Memory, Inc.", O=...).
        $m = [regex]::Match($s, '^CN="([^"]+)"')
        if ($m.Success) { return $m.Groups[1].Value }
        $m = [regex]::Match($s, '^CN=([^,]+)')
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
    }
    return "sconosciuto"
}

# Un indirizzo numerico non dice niente a nessuno: qui si prova a
# risalire al nome del sito, con un tetto di tempo per non bloccare
# tutto quando l'indirizzo non risponde.
$cacheDns = @{}
function NomeHost($ip) {
    if ($script:cacheDns.ContainsKey($ip)) { return $script:cacheDns[$ip] }
    $nome = $ip
    try {
        $t = [System.Net.Dns]::GetHostEntryAsync($ip)
        if ($t.Wait(700) -and $t.Result -and $t.Result.HostName) { $nome = $t.Result.HostName }
    } catch { }
    $script:cacheDns[$ip] = $nome
    return $nome
}

function DischiFissi {
    $d = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.FileSystem -and $_.DriveType -eq 'Fixed' })
    if ($d.Count -eq 0) {
        # Ripiego per sistemi in cui Get-Volume non espone DriveType
        $d = @(Get-PSDrive -PSProvider FileSystem | Where-Object { $null -ne $_.Free } |
               ForEach-Object { [pscustomobject]@{ DriveLetter = $_.Name; Size = $_.Used + $_.Free; SizeRemaining = $_.Free; HealthStatus = $null } })
    }
    return $d
}

# Programmi installati, con le cartelle che si possono attribuire a
# ciascuno (installazione, disinstallatore, icona). Letti una volta sola.
$cacheInstallati = $null
function ProgrammiInstallati {
    if ($null -ne $script:cacheInstallati) { return $script:cacheInstallati }
    $l = New-Object System.Collections.ArrayList
    foreach ($a in (Get-ItemProperty -Path $script:reg -ErrorAction SilentlyContinue)) {
        if (-not $a.DisplayName) { continue }
        $cartelle = @()
        if ($a.InstallLocation) { $cartelle += ([string]$a.InstallLocation).Trim('"').TrimEnd('\') }
        foreach ($campo in @($a.UninstallString, $a.DisplayIcon)) {
            $x = EstraiEseguibile (([string]$campo) -replace ',-?\d+$', '')
            if ($x -and $x -match '^[A-Za-z]:\\' -and $x -notmatch '(?i)\\(msiexec|rundll32)\.exe$') {
                $cartelle += [System.IO.Path]::GetDirectoryName($x)
            }
        }
        $dt = $null
        try { $dt = [datetime]::ParseExact([string]$a.InstallDate, 'yyyyMMdd', $null) } catch { }
        [void]$l.Add([pscustomobject]@{
            Nome = [string]$a.DisplayName; Editore = [string]$a.Publisher; Data = $dt
            Icona = $a.DisplayIcon; Loc = $a.InstallLocation
            Cartelle = @($cartelle | Where-Object { $_ } | Select-Object -Unique)
        })
    }
    $script:cacheInstallati = $l
    return $l
}
function ProprietarioDi($exe) {
    $x = EstraiEseguibile $exe
    if (-not $x -or -not (Test-Path -LiteralPath $x -PathType Leaf)) { return $null }
    $info = $null
    try { $info = (Get-Item -LiteralPath $x -ErrorAction Stop).VersionInfo } catch { }
    return (ProgrammaProprietario $x (ProgrammiInstallati) $info)
}

# ------------------------------------------------------------ CONFERME
# Cose che SOLO tu puoi sapere (es. "questo l'hai installato tu?") non vanno
# indovinate: si chiedono una volta e la risposta si ricorda.
#  - conferme-programmi.json: per nome del programma installato (dalla v2)
#  - conferme-file.json: per IMPRONTA del file (dalla v3). Se il file cambia,
#    anche di un byte, l'impronta cambia e la domanda torna: una conferma
#    data a un programma non copre un malware che ne prende il posto.
$cartellaDati  = Join-Path $env:LOCALAPPDATA 'Sentinella'
$fileConferme  = Join-Path $cartellaDati 'conferme-programmi.json'
$fileConfermeF = Join-Path $cartellaDati 'conferme-file.json'
function CaricaJsonTabella($percorso) {
    $t = @{}
    if (Test-Path -LiteralPath $percorso) {
        try {
            $letto = Get-Content -LiteralPath $percorso -Raw -ErrorAction Stop | ConvertFrom-Json
            foreach ($p in $letto.PSObject.Properties) { $t[$p.Name] = $p.Value }
        } catch { }
    }
    return $t
}
function SalvaJsonTabella($tabella, $percorso) {
    try {
        $c = Split-Path $percorso -Parent
        if (-not (Test-Path -LiteralPath $c)) { New-Item -ItemType Directory -Path $c -Force | Out-Null }
        $tabella | ConvertTo-Json -Depth 4 | Out-File -FilePath $percorso -Encoding utf8
    } catch { }
}
$conferme      = CaricaJsonTabella $fileConferme
$confermeFile  = CaricaJsonTabella $fileConfermeF
function SalvaConferme { SalvaJsonTabella $script:conferme $script:fileConferme }

# Restituisce 'si', 'no', oppure $null se la domanda non e' stata posta
# (modalita' Lampo o silenziosa: li' non si chiede mai nulla).
function ConfermaFile([string]$percorso, [string]$descrizione) {
    $h = Impronta $percorso
    if (-not $h) { return $null }
    if ($script:confermeFile.ContainsKey($h)) { return [string]$script:confermeFile[$h].risposta }
    if ($script:lampo -or $script:silenzioso) { return $null }
    Scrivi "" Gray
    Scrivi "     $descrizione" Yellow
    Scrivi "     file: $(EstraiEseguibile $percorso)" Gray
    $r = ChiediSiNo "       Lo riconosci, l'hai installato tu? [S] si  [N] no/non so (INVIO = no)"
    $risposta = 'no'
    if ($r) { $risposta = 'si' }
    $script:confermeFile[$h] = @{ risposta = $risposta; quando = (Get-Date).ToString('dd/MM/yyyy'); percorso = (EstraiEseguibile $percorso) }
    SalvaJsonTabella $script:confermeFile $script:fileConfermeF
    return $risposta
}
function QuandoConfermato([string]$percorso) {
    $h = Impronta $percorso
    # Solo le conferme positive: un "no" non deve far tacere nessun avviso.
    if ($h -and $script:confermeFile.ContainsKey($h) -and $script:confermeFile[$h].risposta -eq 'si') { return [string]$script:confermeFile[$h].quando }
    return ''
}

# Valuta un file NON firmato che parte da solo (avvio, attivita', servizio)
# e lo segnala al livello giusto:
#   confermato da te (stessa impronta)       -> nota
#   pezzo riconosciuto di un programma installato -> giallo
#   nessuna delle due                         -> rosso
function ValutaNonFirmato([string]$percorso, [string]$descrizione) {
    $hash = Impronta $percorso
    $proprietario = ProprietarioDi $percorso
    $noto = $null
    if ($proprietario) { $noto = ComponenteNoto $proprietario }
    if (-not $noto) { $noto = ComponenteNoto ([System.IO.Path]::GetFileNameWithoutExtension((EstraiEseguibile $percorso))) }
    $risposta = ConfermaFile $percorso $descrizione
    if ($risposta -eq 'si') {
        Nota "   $descrizione - non firmato, riconosciuto da te il $(QuandoConfermato $percorso) (stessa impronta)"
        return
    }
    if ($proprietario) {
        $testo = "$descrizione - NON firmato, ma risulta parte del programma installato '$proprietario'"
        if ($noto) { $testo += " ($noto)" }
        Attenzione "$testo  [SHA256 $hash]"
        return
    }
    Allarme "$descrizione - file NON firmato, non riconducibile a nessun programma installato  [SHA256 $hash]"
}

# Traduzione "\Device\HarddiskVolumeN" -> "C:" per i percorsi salvati da Windows in forma interna.
function MappaVolumi {
    $m = @{}
    try {
        if (-not ('Sentinella.Nativo' -as [type])) {
            Add-Type -Namespace 'Sentinella' -Name 'Nativo' -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@ -ErrorAction Stop
        }
        foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
            $lettera = $d.Name.TrimEnd('\')
            $sb = New-Object System.Text.StringBuilder 1024
            if ([Sentinella.Nativo]::QueryDosDevice($lettera, $sb, 1024) -gt 0) { $m[$sb.ToString()] = $lettera }
        }
    } catch { }
    return $m
}
# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAzvMwZmcNPXcoE
# PnAmN8GLlM2kTOCVV20GXongrQfVOKCCBCowggQmMIICjqADAgECAhBsFNOb1/0T
# iEmLgLsWwl8pMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFNlbnRpbmVsbGEg
# LSBmaXJtYSBjb2RpY2UgKGxvenkpMB4XDTI2MTEyNDA5MTQ1NVoXDTMxMTEyNDA5
# MjQ1NVowKzEpMCcGA1UEAwwgU2VudGluZWxsYSAtIGZpcm1hIGNvZGljZSAobG96
# eSkwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC6qg0jNOiPdZyNKY0U
# GQK6Phvr9OokrbArSlmCe2xlKsw/XCPaOTn4AdzFVTjqyPs/Nzc/v7c0G4vHk2N4
# BcMrNAbsLhJKUH9MKLcxhXfxv5OsCDn0e7/opw/PNKuvwGdU5hFNxZF58hUZWb8u
# 5nFSiEYTno20mhjbOALNzmSq5rMme1oWqcPJYhNWaYMFHBcIP5LtHqUaKk9l+y/Z
# ZCJfmMugalMs4vB90/nZcP+nY89yOP9ubhfW4jPvwKGLxcL1E2HbMwBL7mfUAXNi
# tHem1pUAIlUnCmHF3IUNkfqbc5gppzaMXUrjGwc0z3hAZMe7jBf2cQoQjBkZmw92
# 61Qw1xvcQbl2Uf+53J/bjnaL5mTSC23z+B41kHRqKCgaEYx++S2ETnHP/iK30wHp
# QBlVeji17o1Q+rYhKurSCo/rpYUNYuWjveaIEsE1CC+HkAYwOj1Ow6yFqwv3IM6c
# VftUHr4ohi8qH1mIn0sFyFGpNhsdQQx3v+vHwD+C5qbrYMECAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSgWVtU
# sJIm3AmrnSf7a7fTW+AcDDANBgkqhkiG9w0BAQsFAAOCAYEAgPMQAXl/uTNDe79T
# cjO0KimKaiet/wRlDr4D3cU6NTOjiqtrEZoJCFvB3j2HWsp/2zeQ1s/LVDCypUar
# rRfIqG6Jfwv7C8eYFA0tiHXFcTF+CZudfppJEsjixHfKkD87uAtSmHuWpK2RfeGL
# yxc2i9uT+7eQivgmT7nVD2BPAIgr6RurNL4FoNaXLSt/39T+QbC5ciPF7UAKkEV0
# vV+PQrhWVinRiKRtqYL1MufYzRTMMIj0V4pdNWHKoptf1gRGP/5HzWPRGNI0kDSc
# GgrIEBwgKNovp5XL47/ltqbfIvXgtRbhp9yaNkBWs1nVJsUKHYSoZ/29P8z7YF8s
# PdBfn5jZ4gZJEkEXNUCYHZ2h0Q7cAPMGXtYoqxVPeXonKvc4TNJ5jaKmoaJv8nAq
# eLzl7+2+ZbQuXwBk0vVFltBGCKBFEvyOEleNo68ORavNHRfJK7iLqVPjGhsw5w56
# NCu/2sE+fzB1VsYt40bURsvodSmFo3zrf26iKFAFvQkUJCyDMYICcTCCAm0CAQEw
# PzArMSkwJwYDVQQDDCBTZW50aW5lbGxhIC0gZmlybWEgY29kaWNlIChsb3p5KQIQ
# bBTTm9f9E4hJi4C7FsJfKTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEM
# MQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDe6rslbKYO/JLX
# CK2Roaj64Ti6ld1rbZ3ea6W+ZdSjGzANBgkqhkiG9w0BAQEFAASCAYCZfUOYA5S8
# wHK9E/d3/F+UK8RKrmQ54CoS5XpE+OgFR/OKeCkZv+RNAXxpAeAPTOdKz/Vttgjt
# vq/USy9fERc/ok5A9TzPMIlnqlwlNo7E3pnsaPytxvCELEiCO2pr+LETYnm7/pHA
# O7IK/8hpyTSPh37rUDPvZwNrTodqFgXd0MmaOsRUmIvytzsu/ue4IXifVxW8XMWT
# tMRbADuZ7vaggcQZN/OPCmi6i8MyAVjz9E20Ykez+jxDYSECPn6tIoJx3Al4yf5W
# v+QQvQzjb4K/8fW9+tTbOqzArzDcxdXuOdCPpHGeOfjEmyjffLkKryiXvELusbGI
# MSv1H7ePVp82ZJAnxIJDDxGuJG7C+p6peRDXSbxgdohSWZxQGE+1mbmT+rznWki2
# OCRl3GgcgWpPl0kIiur0Yq0x1w/FtIoUcWsHNXdLv6M1PV0fjXbvoWdkYsGC9OhS
# qn1A95rY56y7PP+Ilhua46gkvBFveqpVQOynrjWFMaMHodj737O7eaU=
# SIG # End signature block
