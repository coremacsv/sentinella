# =====================================================================
#  SENTINELLA - Tracce da infostealer
#  Gli infostealer (Lumma, RedLine, Vidar...) di solito non arrivano da
#  soli: e' la persona a farli partire, convinta da un "cheat", un finto
#  aggiornamento o un finto CAPTCHA. Questi controlli cercano le tracce
#  che quel momento lascia sul PC, anche quando l'antivirus non ha
#  riconosciuto il file.
# =====================================================================

function ProfiliUtente {
    # L'utente corrente sempre; gli altri solo se siamo amministratori.
    $p = @([pscustomobject]@{ Nome = $env:USERNAME; Cartella = $env:USERPROFILE })
    if ($script:admin) {
        foreach ($d in (Get-ChildItem -LiteralPath (Split-Path $env:USERPROFILE -Parent) -Directory -ErrorAction SilentlyContinue)) {
            if ($d.FullName -ieq $env:USERPROFILE -or $d.Name -in @('Public', 'Default', 'Default User', 'All Users')) { continue }
            if (Test-Path -LiteralPath (Join-Path $d.FullName 'AppData')) { $p += [pscustomobject]@{ Nome = $d.Name; Cartella = $d.FullName } }
        }
    }
    return $p
}

function Accorcia([string]$t, [int]$max = 140) {
    $t = ($t -replace '\s+', ' ').Trim()
    if ($t.Length -gt $max) { return $t.Substring(0, $max - 3) + '...' }
    return $t
}

function C_ComandiIncollati {
    $trovati = 0; $guardati = 0
    # 1. Finestra Esegui (Win+R): ClickFix classico.
    # 2. Barra degli indirizzi di Esplora file: variante "FileFix" (2025),
    #    la pagina chiede di incollare il "percorso del documento".
    $fonti = @(
        @{ Chiave = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU';     Nome = 'finestra Esegui (Win+R)' },
        @{ Chiave = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'; Nome = 'barra di Esplora file' }
    )
    foreach ($f in $fonti) {
        if (-not (Test-Path $f.Chiave)) { $guardati++; continue }
        $voci = Leggi { Get-ItemProperty -Path $f.Chiave } "Cronologia $($f.Nome)"
        if ($null -eq $voci) { continue }
        $guardati++
        foreach ($p in $voci[0].PSObject.Properties) {
            if ($script:proprietaPS -contains $p.Name -or $p.Name -eq 'MRUList') { continue }
            $cmd = ([string]$p.Value) -replace '\\1$', ''
            $esito = ComandoIncollatoSospetto $cmd
            if (-not $esito) { continue }
            $trovati++
            $testo = "Comando nella $($f.Nome) - $($esito.Motivo): $(Accorcia $cmd)"
            if ($esito.Livello -ge 2) { Allarme $testo } else { Attenzione $testo }
        }
    }
    # 3. Cronologia di PowerShell (PSReadLine), per ogni utente leggibile.
    foreach ($u in (ProfiliUtente)) {
        $f = Join-Path $u.Cartella 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $righe = Leggi { Get-Content -LiteralPath $f -Tail 5000 } "Cronologia PowerShell di $($u.Nome)"
        if ($null -eq $righe) { continue }
        $guardati++
        $visti = @{}
        foreach ($r in $righe) {
            $esito = ComandoIncollatoSospetto $r
            if (-not $esito -or $visti.ContainsKey($r)) { continue }
            $visti[$r] = $true
            $trovati++
            $testo = "PowerShell ($($u.Nome)) - $($esito.Motivo): $(Accorcia $r)"
            if ($esito.Livello -ge 2) { Allarme $testo } else { Attenzione $testo }
        }
    }
    if ($trovati -eq 0) { Ok "Nessun comando sospetto incollato in Esegui, Esplora file o PowerShell" }
    else {
        SpiegaDinamica `
            "Tra i comandi scritti o incollati sul PC ce n'e' almeno uno che scarica ed esegue codice da internet. E' esattamente il trucco 'ClickFix': una pagina con un finto CAPTCHA o un finto errore ti chiede di premere Win+R e incollare un comando, che in realta' installa un infostealer." `
            "Leggi il comando segnalato: se l'hai scritto tu per installare un programma che conosci, va bene. Se l'hai incollato perche' una pagina te lo chiedeva, considera il PC compromesso: da un ALTRO dispositivo cambia le password importanti e chiudi tutte le sessioni attive (Google, Discord, Steam, banca), poi fai una scansione Completa."
    }
}

# Mark of the Web: Windows annota su ogni file scaricato da dove arriva.
# Leggerla e' gratis e dice subito se il file viene da un sito che conosci.
function OrigineDownload([string]$percorso) {
    try {
        $z = Get-Content -LiteralPath $percorso -Stream Zone.Identifier -ErrorAction Stop
        $url = ($z | Where-Object { $_ -like 'HostUrl=*' } | Select-Object -First 1) -replace '^HostUrl=', ''
        if (-not $url) { $url = ($z | Where-Object { $_ -like 'ReferrerUrl=*' } | Select-Object -First 1) -replace '^ReferrerUrl=', '' }
        if ($url -match '^(?i)https?://([^/:]+)') { return $Matches[1] }
        if ($z -match 'ZoneId=3') { return 'internet' }
    } catch { }
    return $null
}

function C_FileScaricati {
    $cartelle = @(([Environment]::GetFolderPath('UserProfile') + '\Downloads'), [Environment]::GetFolderPath('Desktop')) | Select-Object -Unique
    $limite = (Get-Date).AddDays(-14)
    $eseguibili = @('.exe', '.msi', '.scr', '.com', '.pif')
    $script_ = @('.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.lnk', '.url')
    $archivi = @('.zip', '.rar', '.7z', '.iso', '.img', '.vhd', '.vhdx')
    $n = 0; $segnalati = 0; $letta = $false
    foreach ($c in $cartelle) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        $file = Leggi { Get-ChildItem -LiteralPath $c -File -Force -Recurse -Depth 2 | Where-Object { $_.LastWriteTime -ge $limite -or $_.CreationTime -ge $limite } } "Contenuto di $c"
        if ($null -eq $file) { continue }
        $letta = $true
        foreach ($f in ($file | Sort-Object LastWriteTime -Descending)) {
            $ext = $f.Extension.ToLower()
            if ($ext -notin ($eseguibili + $script_ + $archivi)) { continue }
            # Un collegamento sul Desktop e' normale; scaricato da internet no.
            $origine = OrigineDownload $f.FullName
            if ($ext -in @('.lnk', '.url') -and -not $origine) { continue }
            $n++
            if ($n -gt 25) { continue }
            $da = ''
            if ($origine) { $da = " - scaricato da $origine" }
            $quando = $f.LastWriteTime.ToString('dd/MM/yyyy HH:mm')
            $q = "`"$($f.FullName)`""
            if ($ext -in $eseguibili) {
                if (FirmaValida $f.FullName) { Nota "   $quando  $($f.Name)$da - firmato da $(NomeFirmatario $f.FullName)" }
                elseif (-not $origine) { Nota "   $quando  $($f.Name) - non firmato, creato su questo PC (non scaricato)" }
                elseif (-not (GiaRiconosciuto $q "$quando  $($f.Name)$da")) {
                    $segnalati++
                    $t = "Eseguibile NON firmato scaricato di recente: $($f.FullName)$da ($quando)  [SHA256 $(Impronta $q)]"
                    Attenzione $t
                    if ((StatoConferma $q) -ne 'no') { ProponiFile $q "eseguibile$da il $quando" 1 $t }
                }
            } elseif ($ext -in $script_) {
                if (-not $origine) { Nota "   $quando  $($f.Name) - script creato su questo PC" }
                elseif (-not (GiaRiconosciuto $q "$quando  $($f.Name)$da")) {
                    $segnalati++
                    $t = "Script o collegamento scaricato da internet: $($f.FullName)$da ($quando)"
                    Attenzione $t
                    if ((StatoConferma $q) -ne 'no') { ProponiFile $q "script$da il $quando" 1 $t }
                }
            } else {
                Nota "   $quando  $($f.Name)$da"
            }
        }
    }
    if (-not $letta) { NonVerificato "Nessuna delle cartelle Download/Desktop e' risultata leggibile"; return }
    if ($n -gt 25) { Nota "Altri $($n - 25) file non mostrati." }
    if ($segnalati -eq 0) { Ok "Nessun eseguibile o script non firmato scaricato negli ultimi 14 giorni ($n file a rischio esaminati)" }
    else {
        SpiegaDinamica `
            "Negli ultimi 14 giorni sono arrivati da internet programmi o script senza firma digitale. Non vuol dire che siano infetti, ma e' cosi' che arrivano quasi tutti gli infostealer: un 'cheat', un 'crack', una mod, un finto programma di installazione." `
            "Guarda il nome e il sito di provenienza indicati. Se non sei sicuro di cosa sia, NON aprirlo: cerca l'impronta SHA256 mostrata su virustotal.com (casella Search). Se l'hai gia' aperto e non era quello che credevi, tratta il PC come compromesso."
    }
}

function C_EseguitiDiRecente {
    # BAM (Background Activity Moderator) e' un registro interno di Windows
    # che annota ogni programma avviato, con percorso completo e ora. Resta
    # anche dopo che il file e' stato cancellato: e' cosi' che si vede un
    # "cheat" scaricato, eseguito e poi buttato via.
    if (-not $script:admin) { NonVerificato "Serve l'amministratore per leggere lo storico dei programmi avviati"; return }
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
    if (-not (Test-Path $base)) { NonDisponibile "Storico dei programmi avviati non presente su questa versione di Windows"; return }
    $utenti = Leggi { Get-ChildItem -Path $base } "Storico dei programmi avviati (BAM)"
    if ($null -eq $utenti) { return }
    $mappa = MappaVolumi
    if ($mappa.Count -eq 0) { NonVerificato "Impossibile tradurre i percorsi dei dischi: storico non interpretabile"; return }
    $limite = (Get-Date).AddDays(-14)
    $zoneRischio = @(
        @{ Base = [Environment]::GetFolderPath('UserProfile') + '\Downloads'; Diretto = $false; Nome = 'Download' },
        @{ Base = [Environment]::GetFolderPath('Desktop');                    Diretto = $false; Nome = 'Desktop' },
        @{ Base = $env:TEMP;            Diretto = $true; Nome = 'cartella temporanea' },
        @{ Base = $env:APPDATA;         Diretto = $true; Nome = 'AppData\Roaming' },
        @{ Base = $env:LOCALAPPDATA;    Diretto = $true; Nome = 'AppData\Local' },
        @{ Base = $env:ProgramData;     Diretto = $true; Nome = 'ProgramData' },
        @{ Base = "$env:SystemDrive\Users\Public"; Diretto = $false; Nome = 'cartella Pubblica' }
    )
    $visti = 0; $segnalati = 0
    foreach ($u in $utenti) {
        $voci = Get-ItemProperty -Path $u.PSPath -ErrorAction SilentlyContinue
        if (-not $voci) { continue }
        foreach ($p in $voci.PSObject.Properties) {
            if ($p.Name -notlike '\Device\*' -or -not ($p.Value -is [byte[]]) -or $p.Value.Length -lt 8) { continue }
            $quando = [datetime]::FromFileTimeUtc([BitConverter]::ToInt64($p.Value, 0)).ToLocalTime()
            if ($quando -lt $limite) { continue }
            $visti++
            $percorso = ConvertiPercorsoDispositivo $p.Name $mappa
            $zona = $null
            foreach ($z in $zoneRischio) {
                if (-not $z.Base) { continue }
                $cartellaFile = [System.IO.Path]::GetDirectoryName($percorso)
                if ($z.Diretto) { if ($cartellaFile -ieq $z.Base.TrimEnd('\')) { $zona = $z.Nome } }
                elseif ($percorso.StartsWith($z.Base.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { $zona = $z.Nome }
                if ($zona) { break }
            }
            # Anche un eseguibile lanciato dalla radice di un disco (es. E:\cheat.exe) e' fuori posto.
            if (-not $zona -and $percorso -match '^[A-Za-z]:\\[^\\]+\.exe$') { $zona = 'radice di un disco' }
            if (-not $zona) { continue }
            $q = $quando.ToString('dd/MM/yyyy HH:mm')
            if (-not (Test-Path -LiteralPath $percorso)) {
                $segnalati++
                Attenzione "Avviato il $q da $zona e poi SPARITO dal disco: $percorso"
            } elseif (-not (FirmaValida $percorso)) {
                $pq = "`"$percorso`""
                if (GiaRiconosciuto $pq "$q  $percorso") { continue }
                $segnalati++
                $t = "Avviato il $q da $zona, NON firmato: $percorso  [SHA256 $(Impronta $pq)]"
                Attenzione $t
                if ((StatoConferma $pq) -ne 'no') { ProponiFile $pq "avviato il $q da $zona" 1 $t }
            } else {
                Nota "   $q  $percorso - firmato da $(NomeFirmatario $percorso)"
            }
        }
    }
    if ($segnalati -eq 0) { Ok "Nessun programma non firmato o sparito avviato da cartelle a rischio negli ultimi 14 giorni ($visti avvii esaminati)" }
    else {
        SpiegaDinamica `
            "Windows ha annotato l'avvio di programmi senza firma digitale da cartelle dove i programmi normali non stanno (Download, Desktop, cartelle temporanee), oppure di programmi che dopo l'avvio sono stati cancellati. Un infostealer tipico fa esattamente cosi': parte una volta, ruba, e sparisce." `
            "Per ogni voce chiediti: l'ho avviato io? Se e' un programma che conosci (un installer, un gioco), va bene. Se non lo riconosci, o era un 'cheat'/'crack', da un ALTRO dispositivo cambia le password importanti e chiudi tutte le sessioni attive (Google, Discord, Steam, banca)."
    }
}

function C_Discord {
    $varianti = @('Discord', 'DiscordPTB', 'DiscordCanary', 'DiscordDevelopment')
    $trovato = $false; $guai = 0
    foreach ($u in (ProfiliUtente)) {
        foreach ($v in $varianti) {
            $base = Join-Path $u.Cartella "AppData\Local\$v"
            if (-not (Test-Path -LiteralPath $base)) { continue }
            $indici = @(Get-ChildItem -LiteralPath $base -Directory -Filter 'app-*' -ErrorAction SilentlyContinue |
                        ForEach-Object { Get-ChildItem -LiteralPath (Join-Path $_.FullName 'modules') -Directory -Filter 'discord_desktop_core-*' -ErrorAction SilentlyContinue } |
                        ForEach-Object { Join-Path $_.FullName 'discord_desktop_core\index.js' } |
                        Where-Object { Test-Path -LiteralPath $_ })
            foreach ($i in $indici) {
                $trovato = $true
                $contenuto = $null
                try { $contenuto = [System.IO.File]::ReadAllText($i) } catch { NonVerificato "File di Discord non leggibile: $i" ; continue }
                switch (EsitoIndexDiscord $contenuto) {
                    'integro'   { Nota "   $v ($($u.Nome)): integro" }
                    'mod'       { $guai++; Attenzione "$v ($($u.Nome)): modificato da una mod (BetterDiscord, Vencord o simili) - $i" }
                    'manomesso' { $guai++; Allarme "$v ($($u.Nome)): file di avvio MANOMESSO, tipico dei ladri di account Discord - $i" }
                }
            }
        }
    }
    if (-not $trovato) { NonDisponibile "Discord non installato su questo PC"; return }
    if ($guai -eq 0) { Ok "Discord integro: nessun codice aggiunto al suo avvio" }
    else {
        SpiegaDinamica `
            "Il file con cui Discord si avvia contiene codice in piu' rispetto all'originale. E' il trucco piu' usato per rubare gli account Discord: il codice aggiunto ruba il tuo accesso a ogni avvio, e continua a farlo anche dopo che cambi la password. Se hai installato tu BetterDiscord o Vencord, e' normale che risulti modificato." `
            "Se non hai installato mod: chiudi Discord, disinstallalo, cancella le cartelle %LOCALAPPDATA%\Discord e %APPDATA%\discord, reinstallalo dal sito ufficiale. Poi, da un altro dispositivo, cambia la password di Discord (questo scollega tutte le sessioni) e attiva la verifica in due passaggi."
    }
}

# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAD2695LhkmsZd+
# 7VwlaZR+TxUNRXZ+oTSM6dNeyV3KBaCCBCowggQmMIICjqADAgECAhBsFNOb1/0T
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDPhktRM+TxW3hF
# 0A9DL7uhaqCi0Gyj8ifQw8grQNLbxzANBgkqhkiG9w0BAQEFAASCAYAR8d3Sl4pW
# G5WrYeU9lIAAdo1+0cCAj0jaKQ6p1SyXtweQAO5h5DfOa25Ni+4kt+2AJKnkmnyu
# xcDfYa+8NRurx0gEPvksIbJPrSm0eK8CM2icu1toEf6gJJqGXdaxF48hHmKdwdGd
# fA92WcaenHGoOG04kHUKTNMnR5n/4dYnNCNsJn+LXiYZ/cOCtfoUuixT+9oj/a1s
# 9wmISMlHcs/GE/E1gwTo8jC2bA9u3KQbnbei6iUzxteFpWjh2HNMpisGtiiZlzkR
# fyFNYb6pUnxR1gMMR7MS21TiByafyp3fQWG39xzLSlV+Ku0Fn4yvm6Neyl3u2LzX
# Otby7xQJASLuaiLXFrDymVC/nDMPjDyuXhFaLPsXzwdn/CT/+qAVHnps6ZkneaTx
# 2ZE8HpDQqtiVejPCTKtR7fI2Qb7UUBUXWu3pJ4roH3TinTExSLC49iaE27no0lyL
# geVPGaz1D4Y9mTcrlEEzCuFT547d1JvEk4lH6/t+Sms5CIkcZJedXl4=
# SIG # End signature block
