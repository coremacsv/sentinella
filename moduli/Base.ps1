# =====================================================================
#  SENTINELLA - Base
#  Stato condiviso, funzioni di output, e il "motore" che esegue ogni
#  controllo. Caricato per primo da sentinella.ps1.
#
#  Regola d'oro della v3: un controllo e' "OK" solo se lo DICE
#  esplicitamente (chiamando Ok) e non ha incontrato errori di lettura.
#  Fino alla v2 un errore silenziato o un elenco vuoto per sbaglio
#  finivano mostrati come "OK": per uno strumento di sicurezza e' il
#  difetto peggiore possibile, perche' rassicura proprio quando non ha
#  guardato.
# =====================================================================

$allarmi  = New-Object System.Collections.ArrayList   # sicurezza, grave
$sospetti = New-Object System.Collections.ArrayList   # sicurezza, da guardare
$problemi = New-Object System.Collections.ArrayList   # salute, grave
$avvisi   = New-Object System.Collections.ArrayList   # salute, da guardare
$mancati  = New-Object System.Collections.ArrayList   # controlli (o parti) NON verificati
$diario   = New-Object System.Collections.ArrayList   # tutto, per il report
$reperti  = New-Object System.Collections.ArrayList   # ogni riga, strutturata, per il JSON

# Esito di ogni controllo: 0 ok, 1 da guardare, 2 grave, 3 non applicabile,
# 4 NON VERIFICATO (doveva essere controllabile ma la lettura e' fallita).
$esiti        = New-Object System.Collections.Specialized.OrderedDictionary
$incompleti   = @{}   # titolo -> $true se una parte del controllo non e' stata verificata
$sezioneDi    = @{}
$checkCorrente   = ''
$sezioneCorrente = ''
$nOkCorrente     = 0
$passo           = 0
$spiegazioniDinamiche = @{}

# Modalita' senza domande (uso da riga di comando o attivita' pianificata).
if ($null -eq $silenzioso) { $silenzioso = $false }

function Riga($t) { [void]$script:diario.Add($t) }
function Reperto([string]$livello, [string]$testo) {
    [void]$script:reperti.Add([ordered]@{
        controllo = $script:checkCorrente
        sezione   = $script:sezioneCorrente
        livello   = $livello
        testo     = $testo
    })
}

function SpiegaDinamica([string]$cosa, [string]$fai) {
    if (-not $script:checkCorrente) { return }
    $script:spiegazioniDinamiche[$script:checkCorrente] = @{ Cosa = $cosa; Fai = $fai }
}
function Segna([int]$livello) {
    if (-not $script:checkCorrente) { return }
    $attuale = [int]$script:esiti[$script:checkCorrente]
    # 3 e 4 sono stati "senza esito": un reperto vero (1 o 2) li sostituisce.
    if ($attuale -ge 3) { $script:esiti[$script:checkCorrente] = $livello; return }
    if ($attuale -lt $livello) { $script:esiti[$script:checkCorrente] = $livello }
}

function Titolo($t) {
    $script:passo++
    $script:checkCorrente = $t
    $script:esiti[$t] = 0
    $script:nOkCorrente = 0
    $script:sezioneDi[$t] = $script:sezioneCorrente
    if (-not $script:silenzioso) {
        Write-Host ""
        Write-Host ("-" * 74) -ForegroundColor DarkGray
        Write-Host ("  [{0}/{1}]  {2}" -f $script:passo, $script:TOTPASSI, $t) -ForegroundColor Cyan
        Write-Host ("-" * 74) -ForegroundColor DarkGray
    }
    Riga ""
    Riga "--- $t ---"
}
function Sezione($t) {
    $script:sezioneCorrente = $t
    if (-not $script:silenzioso) {
        Write-Host ""
        Write-Host ("=" * 74) -ForegroundColor White
        Write-Host "   $t" -ForegroundColor White
        Write-Host ("=" * 74) -ForegroundColor White
    }
    Riga ""
    Riga "=== $t ==="
}
function Scrivi([string]$testo, [string]$colore) {
    if (-not $script:silenzioso) { Write-Host $testo -ForegroundColor $colore }
}

function Ok($m)         { Scrivi "  [ OK ] $m" Green;  Riga "  [OK] $m"; Reperto 'ok' $m; $script:nOkCorrente++ }
function Nota($m)       { Scrivi "  [ .. ] $m" Gray;   Riga "  [..] $m"; Reperto 'nota' $m }
function Attenzione($m) { Scrivi "  [ !! ] $m" Yellow; Riga "  [!!] $m"; Reperto 'sicurezza-da-guardare' $m; [void]$script:sospetti.Add($m); Segna 1 }
function Allarme($m)    { Scrivi "  [ XX ] $m" Red;    Riga "  [XX] $m"; Reperto 'sicurezza-grave' $m;       [void]$script:allarmi.Add($m);  Segna 2 }
function Avviso($m)     { Scrivi "  [ !! ] $m" Yellow; Riga "  [!!] $m"; Reperto 'salute-da-guardare' $m;    [void]$script:avvisi.Add($m);   Segna 1 }
function Problema($m)   { Scrivi "  [ XX ] $m" Red;    Riga "  [XX] $m"; Reperto 'salute-grave' $m;          [void]$script:problemi.Add($m); Segna 2 }
function NonDisponibile($m) {
    # "Non applicabile su questo PC" (es. niente Defender perche' c'e' un
    # altro antivirus): non e' un problema, ma nemmeno un via libera.
    Scrivi "  [ -- ] $m" DarkGray; Riga "  [--] $m"; Reperto 'non-applicabile' $m
    if ($script:checkCorrente -and [int]$script:esiti[$script:checkCorrente] -eq 0) { $script:esiti[$script:checkCorrente] = 3 }
}
function NonVerificato($m) {
    # Il controllo DOVEVA poter guardare questo punto e non ci e' riuscito
    # (permessi, servizio spento, errore di Windows). Non e' mai un "OK".
    Scrivi "  [ ?? ] $m" Magenta; Riga "  [??] $m"; Reperto 'non-verificato' $m
    [void]$script:mancati.Add("$($script:checkCorrente): $m")
    if ($script:checkCorrente) {
        $script:incompleti[$script:checkCorrente] = $true
        $attuale = [int]$script:esiti[$script:checkCorrente]
        if ($attuale -eq 0 -or $attuale -eq 3) { $script:esiti[$script:checkCorrente] = 4 }
    }
}

function Esiste($cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# Legge un dato da Windows trasformando OGNI errore in un "non verificato"
# esplicito, invece di lasciarlo sparire nel silenzio. Restituisce $null
# se la lettura e' fallita: chi chiama DEVE distinguere $null (non so)
# da un elenco vuoto (ho guardato, non c'e' niente) - per questo i
# risultati vuoti tornano come array vuoto @(), mai come $null.
function Leggi([scriptblock]$comando, [string]$cosa) {
    try {
        $ErrorActionPreference = 'Stop'
        $r = & $comando
        if ($null -eq $r) { return ,@() }
        return ,@($r)
    } catch {
        NonVerificato ("{0}: lettura non riuscita ({1})" -f $cosa, (MessaggioBreve $_))
        return $null
    }
}
# Come Leggi, ma per il registro eventi: "nessun evento trovato" e' una
# risposta valida (elenco vuoto), non un errore.
function LeggiEventi([hashtable]$filtro, [string]$cosa) {
    try {
        return ,@(Get-WinEvent -FilterHashtable $filtro -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or $_.Exception.Message -match 'No events were found|Nessun evento') { return ,@() }
        NonVerificato ("{0}: registro eventi non leggibile ({1})" -f $cosa, (MessaggioBreve $_))
        return $null
    }
}
function MessaggioBreve($errore) {
    $t = [string]$errore.Exception.Message
    $t = ($t -split "`r?`n")[0].Trim()
    if ($t.Length -gt 110) { $t = $t.Substring(0, 107) + '...' }
    return $t
}

# Il motore: esegue un controllo, intercetta qualsiasi interruzione, e
# applica la regola d'oro (niente Ok esplicito = non verificato).
function EseguiControllo([string]$titolo, [scriptblock]$azione) {
    Titolo $titolo
    try {
        & $azione
    } catch {
        NonVerificato ("il controllo si e' interrotto: {0}" -f (MessaggioBreve $_))
        Riga ("      dettaglio tecnico: {0} @ {1}" -f $_.FullyQualifiedErrorId, $_.InvocationInfo.PositionMessage -replace "`r?`n", ' ')
    }
    $e = [int]$script:esiti[$titolo]
    if ($e -eq 0 -and $script:nOkCorrente -eq 0) {
        NonVerificato "il controllo non ha prodotto un esito verificato: non lo considero superato"
    }
}

# Una scansione antivirus puo' durare minuti senza stampare una riga, e
# una finestra immobile sembra bloccata. Il lavoro viene quindi avviato in
# parallelo e nel frattempo si mostra un indicatore che gira, con il tempo
# trascorso: cosi' si vede sempre che il programma sta lavorando.
function Attendi($lavoro, $etichetta) {
    if (-not $lavoro) {
        Scrivi "      [x]  $etichetta  -  non e' stato possibile avviarla" Yellow
        return $false
    }
    $rot = @('|', '/', '-', '\')
    $i = 0
    $t0 = Get-Date
    while ($lavoro.State -in @('Running', 'NotStarted')) {
        if (-not $script:silenzioso) {
            $s = [int]((Get-Date) - $t0).TotalSeconds
            $t = "      [{0}]  {1}  in esecuzione...  {2:00}:{3:00}" -f $rot[$i % 4], $etichetta, [int][Math]::Floor($s / 60), ($s % 60)
            Write-Host ("`r" + $t.PadRight(76)) -NoNewline -ForegroundColor DarkCyan
        }
        Start-Sleep -Milliseconds 200
        $i++
    }
    $riuscito = ($lavoro.State -eq 'Completed')
    $null = Receive-Job $lavoro -ErrorAction SilentlyContinue
    Remove-Job $lavoro -Force -ErrorAction SilentlyContinue
    $tot = [int]((Get-Date) - $t0).TotalSeconds
    if (-not $script:silenzioso) {
        Write-Host ("`r" + (" " * 76)) -NoNewline
        if ($riuscito) { Write-Host ("`r      [v]  {0}  -  completata in {1} secondi" -f $etichetta, $tot) -ForegroundColor DarkGray }
        else { Write-Host ("`r      [x]  {0}  -  NON completata" -f $etichetta) -ForegroundColor Yellow }
    }
    return $riuscito
}

# Stessa idea per un programma esterno (usato da sfc, che non e' un job).
function AttendiProcesso($proc, $etichetta) {
    $rot = @('|', '/', '-', '\')
    $i = 0
    $t0 = Get-Date
    while (-not $proc.HasExited) {
        if (-not $script:silenzioso) {
            $s = [int]((Get-Date) - $t0).TotalSeconds
            $t = "      [{0}]  {1}  in esecuzione...  {2:00}:{3:00}" -f $rot[$i % 4], $etichetta, [int][Math]::Floor($s / 60), ($s % 60)
            Write-Host ("`r" + $t.PadRight(76)) -NoNewline -ForegroundColor DarkCyan
        }
        Start-Sleep -Milliseconds 200
        $i++
    }
    if (-not $script:silenzioso) {
        $tot = [int]((Get-Date) - $t0).TotalSeconds
        Write-Host ("`r" + (" " * 76)) -NoNewline
        Write-Host ("`r      [v]  {0}  -  completata in {1} secondi" -f $etichetta, $tot) -ForegroundColor DarkGray
    }
}

# Domanda si/no che in modalita' silenziosa non blocca mai: restituisce $null
# ("non chiesto"), e chi chiama tratta il caso come una risposta mancante.
function ChiediSiNo([string]$domanda) {
    if ($script:silenzioso) { return $null }
    $r = Read-Host $domanda
    return ($r -match '^\s*[SsYy]')
}

# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCq+fpZorw/hoMa
# pGhFM5+/sobRLLPNFKhLsFMxn+4BM6CCBCowggQmMIICjqADAgECAhBsFNOb1/0T
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDB1xJ11Ba2tdpN
# bsFKFcHLooVJP8GQKUDB2nCAOxBVOzANBgkqhkiG9w0BAQEFAASCAYAAQ0bvQI2B
# Tj1OH+9akrnlRiqDlMn9rRE9FpXcA01FWpgMUDVU6sGrhQFHzkwV5LCenjREL6MC
# IIDAgrBzSengttjGXzA1xi+umM+qrwYJbjbdc356Bcq+qC4itaujEbhdtTtYqNK6
# mErAqE1JMd7wN0Y4EF7MNlmgHojCfie8dECpYUdw/c2BBjRScjFxGWvK4As/Y4yT
# L6SDDg1tNUCDv60JWgYPocmEaJbG2+LsMHU0RpOGH9YcAKqr0dWb2AM5USVjj/OE
# Ftb+fA47VUVPw+TvJlivA+NKFy9TXO9alSv0BsiJPVdgtXqN8Ll2IWr8v8t5A5vv
# wT4facZMX/e00vLdYJ48EX0EDkQ+lYjxTLDTaWudF/11B0q2DTqgEBUk7sggqYan
# bHZSfLaylh/I1TfiQ7RAYKo47vAc49NUhhOje98A/2JLaQBJdsZx25moYZir1gZV
# dAAl15cb6ZIJs5ea+TGanG2ntNnNEUBlz7ks3OS/GI0iMTG9tbnmvIk=
# SIG # End signature block
