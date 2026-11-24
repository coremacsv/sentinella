# =====================================================================
#  SENTINELLA - Analisi
#  Le funzioni che DECIDONO (cosa e' sospetto, cosa e' normale). Sono
#  tenute separate dai controlli che leggono il sistema per un motivo
#  preciso: cosi' si possono provare con dati finti nei test automatici
#  (cartella test\), senza bisogno di un PC infetto per sapere se
#  l'allarme scatta davvero.
# =====================================================================

# Solo Windows e Programmi richiedono l'amministratore per scriverci: tutto il
# resto (profilo utente, altri dischi) va verificato con la firma digitale.
$cartelleDiSistema = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) |
                     Where-Object { $_ } | Select-Object -Unique
$eccezioniDiSistema = @("$env:SystemRoot\Temp", "$env:SystemRoot\Tasks", "$env:SystemRoot\Tracing", "$env:SystemRoot\System32\Tasks")

# Da una riga di comando (virgolette, parametri, %variabili%) ricava il solo file.
function EstraiEseguibile($comando) {
    if ([string]::IsNullOrWhiteSpace($comando)) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables([string]$comando).Trim()
    if ($c.StartsWith('"')) {
        $fine = $c.IndexOf('"', 1)
        if ($fine -gt 0) { return $c.Substring(1, $fine - 1) }
        return $c.Trim('"')
    }
    $m = [regex]::Match($c, '^.+?\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|dll|msi)(?=\s|,|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Value }
    return $c
}

function EsuPercorsoSospetto($p) {
    $x = EstraiEseguibile $p
    if (-not $x) { return $false }
    if ($x -match '^\\\\') { return $true }
    if ($x -notmatch '^[A-Za-z]:\\') { return $false }
    foreach ($e in $script:eccezioniDiSistema) { if ($x.StartsWith("$e\", [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    foreach ($s in $script:cartelleDiSistema) { if ($x.StartsWith("$s\", [StringComparison]::OrdinalIgnoreCase)) { return $false } }
    return $true
}

# I programmi che si auto-aggiornano (OneDrive) lasciano comandi una tantum come
# "cmd /c del ...": cancellano un file e basta, non fanno partire nulla.
function ComandoPulizia($comando) {
    $c = [Environment]::ExpandEnvironmentVariables([string]$comando)
    return ($c -match '(?i)^"?([a-z]:\\[^"]*\\)?cmd(\.exe)?"?\s+(/\w+\s+)*(del|erase|rd|rmdir)\s')
}

# Il malware si nasconde spesso dietro programmi di Windows perfettamente firmati
# (powershell, wscript, rundll32...): quello che conta e' cosa gli viene fatto eseguire.
function ComandoSospetto($comando) {
    if ([string]::IsNullOrWhiteSpace($comando)) { return $false }
    $c = [Environment]::ExpandEnvironmentVariables([string]$comando)
    if ($c -notmatch '(?i)(^|[\\\s"''])(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil)(\.exe)?(["''\s]|$)') { return $false }
    if (ComandoPulizia $c) { return $false }
    if ($c -match '(?i)\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}|\s-w(indowstyle)?\s+h(idden)?\b|frombase64string|downloadstring|downloadfile|invoke-webrequest|invoke-expression|\biex\b|https?://') { return $true }
    foreach ($m in [regex]::Matches($c, '(?i)[a-z]:\\[^"'']+?\.(ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd|dll|exe|scr)\b')) {
        if (EsuPercorsoSospetto $m.Value) { return $true }
    }
    return $false
}

# Un comando incollato a mano (Win+R, PowerShell) e' la firma degli attacchi
# "ClickFix": una pagina finta (finto CAPTCHA, finto errore) ti chiede di
# premere Win+R e incollare. Restituisce @{ Livello; Motivo } oppure $null.
#   Livello 2 = schema tipico dell'attacco (scarica-ed-esegui, codice
#               offuscato, frasi da finto CAPTCHA)
#   Livello 1 = scarica qualcosa da internet: anche chi installa programmi
#               da riga di comando lo fa, quindi va solo riconosciuto
function ComandoIncollatoSospetto([string]$testo) {
    if ([string]::IsNullOrWhiteSpace($testo)) { return $null }
    $t = $testo
    if ($t -match "(?i)(not a robot|non sono un robot|i am human|captcha|verification id|verifica (umana|id)|ray id|cloudflare)") {
        return @{ Livello = 2; Motivo = "frase tipica dei finti CAPTCHA (attacco ClickFix)" }
    }
    if ($t -match '(?i)\bmshta(\.exe)?\b.*https?://|\bmshta(\.exe)?\s+(vbscript|javascript):') {
        return @{ Livello = 2; Motivo = "mshta che apre codice da internet" }
    }
    if ($t -match '(?i)\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string') {
        return @{ Livello = 2; Motivo = "codice nascosto (offuscato in base64)" }
    }
    $scarica = $t -match '(?i)https?://|\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-bitstransfer|certutil.*-urlcache|\bcurl(\.exe)?\b|\bwget\b'
    $esegue  = $t -match '(?i)\biex\b|invoke-expression|\|\s*(powershell|pwsh|cmd)\b|start-process|\.exe\b|rundll32|regsvr32'
    $nascosto = $t -match '(?i)-w(indowstyle)?\s+h(idden)?\b|-nop\b|-noprofile.*-ep\s+bypass|-executionpolicy\s+bypass'
    if ($scarica -and $esegue -and $nascosto) { return @{ Livello = 2; Motivo = "scarica ed esegue codice da internet, in una finestra nascosta" } }
    if ($scarica -and $esegue) { return @{ Livello = 1; Motivo = "scarica ed esegue codice da internet (riconoscilo: lo hai scritto tu?)" } }
    return $null
}

# Il file index.js di Discord, se integro, contiene una sola istruzione che
# carica il programma vero. I "token grabber" ci aggiungono il loro codice,
# cosi' rubano l'accesso al tuo account a ogni avvio di Discord, anche
# dopo che hai cambiato la password. Alcune mod legittime (BetterDiscord,
# Vencord) modificano lo stesso file: vanno riconosciute, non accusate.
function EsitoIndexDiscord([string]$contenuto) {
    if ($null -eq $contenuto) { return 'illeggibile' }
    $c = ($contenuto -replace '\s+', ' ').Trim()
    if ($c -match "^module\.exports\s*=\s*require\(\s*['""]\./core\.asar['""]\s*\)\s*;?$") { return 'integro' }
    if ($c -match '(?i)betterdiscord|vencord|vesktop|replugged|powercord|openasar|equicord') { return 'mod' }
    return 'manomesso'
}

# Un file non firmato e' sospetto a meno che non sia, con buona
# probabilita', un pezzo di un programma che risulta installato.
# Due prove indipendenti, devono valere ENTRAMBE:
#   1. il file sta nella cartella di quel programma (InstallLocation, o la
#      cartella del suo disinstallatore o della sua icona)
#   2. i dati interni del file (nome prodotto/azienda) citano quel programma
# Un malware che si piazza nella cartella di un altro programma di solito
# non si preoccupa di copiarne anche il nome prodotto; se lo fa, la voce
# resta comunque segnalata (in giallo, non sparisce).
function ProgrammaProprietario([string]$exe, $installati, $infoFile) {
    if (-not $exe -or -not $installati) { return $null }
    $cartella = [System.IO.Path]::GetDirectoryName($exe)
    if (-not $cartella) { return $null }
    $prodotto = ''
    if ($infoFile) { $prodotto = "$($infoFile.ProductName) $($infoFile.CompanyName) $($infoFile.FileDescription)" }
    foreach ($p in $installati) {
        $vicino = $false
        foreach ($c in $p.Cartelle) {
            if (-not $c) { continue }
            if ($cartella.TrimEnd('\') -ieq $c.TrimEnd('\') -or $cartella.StartsWith($c.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { $vicino = $true; break }
        }
        if (-not $vicino) { continue }
        # Prima parola significativa del nome del programma (es. "Equalizer"
        # da "Equalizer APO"): basta che compaia nei dati interni del file.
        $parole = @(([string]$p.Nome -split '[\s\-_.()]+') | Where-Object { $_.Length -ge 4 -and $_ -notmatch '^\d' })
        foreach ($w in $parole) {
            if ($prodotto -and $prodotto.IndexOf($w, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $p.Nome }
        }
    }
    return $null
}

# Un aggiornamento cambia solo il numero di versione nel percorso: non e' una voce nuova.
function SenzaVersione($voce) { return ([string]$voce -replace '(?<=\\)\d+(\.\d+)+(?=\\)', '*') }

# ---------------------------------------------------------------- HARDWARE

# Mette insieme gli errori hardware irreversibili (WHEA) e i riavvii
# improvvisi, e trae la conclusione che fino alla v2 andava fatta a mano:
#   - errore seguito entro 2 minuti da un riavvio = l'errore HA causato il riavvio
#   - sempre lo stesso core = quel core e' debole o spinto troppo (undervolt
#     per-core, Curve Optimizer)
#   - core diversi = il problema e' in cio' che i core condividono
#     (collegamento con la RAM, tensioni, risparmio energetico)
# $errori: oggetti con Tempo [datetime], ApicId [int o $null], Componente [string]
# $riavvii: elenco di [datetime] (Kernel-Power 41)
function AnalizzaWhea($errori, $riavvii, [bool]$smt) {
    $r = [ordered]@{ Totale = 0; ConRiavvio = 0; Core = @(); Processore = 0; Diagnosi = 'nessuno' }
    $lista = @($errori)
    $r.Totale = $lista.Count
    if ($r.Totale -eq 0) { return $r }
    $core = @{}
    foreach ($e in $lista) {
        foreach ($t in @($riavvii)) {
            if ([Math]::Abs((([datetime]$t) - ([datetime]$e.Tempo)).TotalSeconds) -le 120) { $r.ConRiavvio++; break }
        }
        if ($null -ne $e.ApicId -and "$($e.ApicId)" -ne '') {
            $r.Processore++
            $n = [int]$e.ApicId
            if ($smt) { $n = [int][Math]::Floor($n / 2) }
            $core[$n] = $true
        }
    }
    $r.Core = @($core.Keys | Sort-Object)
    if ($r.Processore -eq 0) { $r.Diagnosi = 'non-processore' }
    elseif ($r.Core.Count -eq 1 -and $r.Processore -ge 2) { $r.Diagnosi = 'stesso-core' }
    elseif ($r.Core.Count -ge 2) { $r.Diagnosi = 'core-diversi' }
    else { $r.Diagnosi = 'singolo' }
    return $r
}

# I "blocchi temporanei" di Windows (LiveKernelEvent) hanno un codice che
# dice CHI si e' bloccato: quelli qui sotto riguardano la scheda video.
function OrigineBlocco([string]$codice) {
    $c = ([string]$codice).Trim().ToLower().TrimStart('0x')
    if ($c -in @('117', '141', '193', '1b8', '1a1', '1a8', '15f')) { return 'scheda video' }
    if ($c -eq '124') { return 'errore hardware' }
    if ($c -in @('15c', '15d', '15e')) { return 'connessione di rete o USB' }
    return 'componente di sistema'
}

# Un codice di errore di Gestione dispositivi tradotto in qualcosa di utile.
function SpiegaCodicePeriferica([int]$codice) {
    switch ($codice) {
        1  { return 'configurato male' }
        10 { return 'non riesce ad avviarsi' }
        22 { return 'disattivato (lo hai spento tu o un programma)' }
        28 { return 'manca il driver' }
        31 { return 'driver non caricato' }
        43 { return "Windows l'ha fermato perche' ha segnalato un guasto: per l'USB quasi sempre cavo, porta o alimentazione" }
        45 { return 'non collegato in questo momento' }
        default { return "codice $codice" }
    }
}
function NomePeriferica($pnp) {
    if ($pnp.Name) { return [string]$pnp.Name }
    if ($pnp.Description) { return [string]$pnp.Description }
    $id = [string]$pnp.PNPDeviceID
    if ($id -match '^USB\\VID_0000') { return "Dispositivo USB non riconosciuto ($id)" }
    if ($id) { return "Periferica senza nome ($id)" }
    return 'Periferica senza nome'
}

# BAM (registro di Windows) salva i percorsi come "\Device\HarddiskVolume3\..."
# invece di "C:\...": $mappa traduce il primo nel secondo.
function ConvertiPercorsoDispositivo([string]$p, [hashtable]$mappa) {
    if (-not $p) { return $p }
    foreach ($k in $mappa.Keys) {
        if ($p.StartsWith($k + '\', [StringComparison]::OrdinalIgnoreCase)) { return $mappa[$k] + $p.Substring($k.Length) }
    }
    return $p
}

# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDuowDimx8CbwUL
# ko5dINswDsnsXBOeR5QHMnN4Sp/DqKCCBCowggQmMIICjqADAgECAhBsFNOb1/0T
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBQIwvZkYp1CP22
# kZedAKXG82fb3+U+qBj4EiYZ7iu8YzANBgkqhkiG9w0BAQEFAASCAYBrKX2wcW4t
# BDPLhrXUO8926fMwS3i3OBUaVhBqfZc3zXSqNn4PbgWrjfgYJAiVIfmcXbhm9mgm
# pglSDLwId4V8qSLqe9H/84DFSMhv0QWw6fVc7N29Jah5hrhMFo3fIrFXctg2Lw9H
# +tib8fsty5miMgvAEsM1+T2aT/ILAjo25GEN9PWJYAtHTjaJGVXZXKsH2BXF6ekV
# b0SPIqnyDHV+ig2VoRrJQaaY8RyBl7kBt3MRtsN+sXUciHS3H20SBOambDsfpu4G
# YWpexl/zEXGJDN4x6ffTL+XzO+1jCR6obA+8eSAlDT1+zyK216grGqwhcQmRbtVP
# 4W1y2L7453tw4pq/wrKlsLanOtHKjSd11Mp+p0xn0lohFduzLohPOL49t6dLeR2y
# e0RpsU01Ww214kLYttnTioEQBw26EnZEldPo2DocIyBelkLPpfma3V69I2GAsEva
# YFwzi92WjOAzUwiPAqD9rVEPSc7cKuCJLVJtpP7rWJf0ZfNHqDdQGOo=
# SIG # End signature block
