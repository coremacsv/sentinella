# =====================================================================
#  SENTINELLA - Parte C: esame antivirus su tutti i dischi
# =====================================================================

function C_EsameAntivirus {
    if (-not (Esiste 'Start-MpScan')) { NonDisponibile "Windows Defender non presente: esegui a mano una scansione col tuo antivirus"; return }
    $inizioEsame = Get-Date
    if ($script:completa) {
        Scrivi "  Scansione COMPLETA: ogni file di tutti i dischi." Yellow
        Scrivi "  Da 30 minuti a qualche ora. Puoi continuare a usare il PC." Gray
        Nota "Modalita': ogni file di tutti i dischi fissi"
        $esameOk = Attendi (Start-MpScan -ScanType FullScan -AsJob) "scansione completa di tutti i dischi"
        $fineEsame = (Get-MpComputerStatus -ErrorAction SilentlyContinue).FullScanEndTime
        if ($esameOk -and $fineEsame -and $fineEsame -ge $inizioEsame) { Ok "Scansione completa terminata" }
        else { NonVerificato "La scansione completa non risulta conclusa: il risultato non copre tutti i file" }
    } else {
        # La scansione "rapida" di Defender guarda solo il disco di sistema.
        # Qui invece cerchiamo su TUTTI i dischi i file a rischio aggiunti di
        # recente e li facciamo esaminare: e' il punto in cui si nascondono
        # gli installer infetti, anche su dischi mai formattati.
        Scrivi "  Cerco file a rischio recenti su tutti i dischi..." Gray
        $estRischio = @('.exe','.msi','.bat','.cmd','.ps1','.vbs','.js','.jse','.scr','.hta','.zip','.rar','.7z','.iso','.dll')
        $limite = (Get-Date).AddDays(-45)
        $saltaCartelle = @('Windows','Program Files','Program Files (x86)','ProgramData','$Recycle.Bin','System Volume Information','Recovery')
        $cartelle = @{}
        $nFile = 0
        foreach ($v in $script:dischi) {
            $radice = "$($v.DriveLetter):\"
            foreach ($sub in (Get-ChildItem -LiteralPath $radice -Force -ErrorAction SilentlyContinue)) {
                if ($sub.PSIsContainer -and ($saltaCartelle -contains $sub.Name)) { continue }
                $mostra = $sub.FullName
                if ($mostra.Length -gt 52) { $mostra = $mostra.Substring(0, 49) + '...' }
                if (-not $script:silenzioso) { Write-Host ("`r      esploro  " + $mostra.PadRight(56) + " trovati: $nFile") -NoNewline -ForegroundColor DarkCyan }
                $trovati = Get-ChildItem -LiteralPath $sub.FullName -Recurse -File -Force -Depth 5 -ErrorAction SilentlyContinue |
                           Where-Object { $estRischio -contains $_.Extension.ToLower() -and $_.LastWriteTime -ge $limite }
                foreach ($f in $trovati) { $cartelle[$f.DirectoryName] = $true; $nFile++ }
            }
        }
        if (-not $script:silenzioso) { Write-Host ("`r" + (" " * 78)) -NoNewline; Write-Host "`r" -NoNewline }
        # Le parentesi servono: in PowerShell la virgola lega piu' del "+", e
        # senza di esse i tre percorsi diventavano UNA stringa inesistente
        # (bug presente fino alla v2.2: Download e Desktop mai esaminati).
        foreach ($c in @(([Environment]::GetFolderPath('UserProfile') + '\Downloads'), [Environment]::GetFolderPath('Desktop'), $env:TEMP)) {
            if (Test-Path -LiteralPath $c) { $cartelle[$c] = $true }
        }
        # Una cartella dentro un'altra gia' in elenco e' ridondante.
        $ordinate = @($cartelle.Keys) | Sort-Object { $_.Length }
        $finali = New-Object System.Collections.ArrayList
        foreach ($c in $ordinate) {
            # La radice di un disco farebbe scansionare l'INTERO disco: si
            # esaminano invece i singoli file trovati li' dentro.
            if ($c -match '^[A-Za-z]:\\$') {
                foreach ($f in (Get-ChildItem -LiteralPath $c -File -Force -ErrorAction SilentlyContinue |
                                Where-Object { $estRischio -contains $_.Extension.ToLower() -and $_.LastWriteTime -ge $limite })) {
                    [void]$finali.Add($f.FullName)
                }
                continue
            }
            $dentro = $false
            foreach ($g in $finali) { if ($c.StartsWith($g + '\', [StringComparison]::OrdinalIgnoreCase)) { $dentro = $true; break } }
            if (-not $dentro) { [void]$finali.Add($c) }
        }
        $elenco = @($finali) | Select-Object -First 40
        Nota "$nFile file a rischio recenti in $($cartelle.Count) cartelle su $(@($script:dischi).Count) dischi"
        Nota "Dopo aver unito le cartelle annidate: $($finali.Count) punti da esaminare"
        $esamiFalliti = 0
        if (-not (Attendi (Start-MpScan -ScanType QuickScan -AsJob) "memoria e punti di avvio")) { $esamiFalliti++ }
        $i = 0
        foreach ($c in $elenco) {
            $i++
            $breve = $c
            if ($breve.Length -gt 48) { $breve = $breve.Substring(0, 22) + '...' + $breve.Substring($breve.Length - 23) }
            if (-not (Attendi (Start-MpScan -ScanPath $c -ScanType CustomScan -AsJob) ("({0}/{1}) {2}" -f $i, $elenco.Count, $breve))) { $esamiFalliti++ }
        }
        if ($esamiFalliti -gt 0) { NonVerificato "$esamiFalliti esami antivirus non si sono conclusi (a volte perche' Defender ne stava gia' facendo uno): il risultato e' parziale" }
        else { Ok "Esaminate memoria, punti di avvio e $($elenco.Count) punti scelti" }
        if ($finali.Count -gt $elenco.Count) { Attenzione "Esaminati solo $($elenco.Count) punti su $($finali.Count): per gli altri serve la scansione completa" }
        Nota "Per aprire OGNI file di ogni disco serve la scansione completa."
    }

    # 'IsActive' di Get-MpThreat NON e' affidabile (torna falso da solo dopo
    # pochi secondi): si guardano fatti diretti - eseguita? rimossa? il file
    # e' ancora sul disco?
    $trovate = Leggi { Get-MpThreat } "Minacce trovate da Defender"
    if ($null -eq $trovate) { return }
    if ($trovate.Count -eq 0) { Ok "Nessuna minaccia rilevata"; return }
    $dettagli = Leggi { Get-MpThreatDetection } "Dettagli delle minacce"
    if ($null -eq $dettagli) { $dettagli = @() }
    $peggiorAV = 0
    foreach ($t in $trovate) {
        $det = $dettagli | Where-Object { $_.ThreatID -eq $t.ThreatID } | Sort-Object LastThreatStatusChangeTime -Descending | Select-Object -First 1
        $ancoraPresente = $false
        if ($det) {
            foreach ($r in $det.Resources) {
                $p = $r -replace '^file:_', ''
                if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) { $ancoraPresente = $true }
            }
        }
        $azioneOk = $det -and $det.ActionSuccess
        if ($ancoraPresente -or ($t.DidThreatExecute -and -not $azioneOk)) {
            Allarme "MINACCIA ATTIVA: $($t.ThreatName) - presente sul disco o non rimossa con successo"
            if ($peggiorAV -lt 2) { $peggiorAV = 2 }
        } elseif ($t.ThreatName -like 'VulnerableDriver:*') {
            Nota "$($t.ThreatName) - driver legittimo con una falla nota (non un virus), bloccato da Defender: non servono altre azioni"
        } elseif ($t.DidThreatExecute) {
            Attenzione "$($t.ThreatName) - ha girato sul PC, rimossa con successo da Defender"
            if ($peggiorAV -lt 1) { $peggiorAV = 1 }
        } else {
            Nota "$($t.ThreatName) - rilevata e rimossa, MAI eseguita sul PC: nessun rischio reale corso"
        }
    }
    if ($peggiorAV -eq 0) { Ok "Nessuna minaccia attiva rilevata" }
    elseif ($peggiorAV -eq 1) {
        SpiegaDinamica `
            "Windows Defender ha trovato ed eliminato con successo una minaccia che pero' ha fatto in tempo a girare sul PC prima di essere bloccata." `
            "Non serve rimuovere nulla, Defender l'ha gia' fatto. Per sicurezza, dato che ha girato, cambia le password dei servizi importanti da un altro dispositivo e chiudi le sessioni attive (Google, Discord, Steam)."
    } else {
        SpiegaDinamica `
            "Windows Defender ha trovato una minaccia che ha effettivamente girato sul PC (o il cui file e' ancora presente / non rimosso con successo)." `
            "Sicurezza di Windows > Protezione da virus e minacce > Cronologia protezione, e segui le indicazioni per rimuoverla. Poi cambia le password dei servizi importanti da un altro dispositivo e chiudi le sessioni attive."
    }
}

# Defender Offline fa ripartire il PC in un ambiente minimo, dove un malware
# non puo' nascondersi perche' non e' in esecuzione: vede anche i rootkit.
# E' l'unica azione di Sentinella che cambia qualcosa (riavvia il PC), per
# questo va chiesta con una conferma esplicita e mai in modalita' silenziosa.
function OffriScansioneOffline {
    if ($script:silenzioso -or -not (Esiste 'Start-MpWDOScan') -or -not $script:admin) { return }
    Write-Host ""
    Write-Host ("   " + ("-" * 68)) -ForegroundColor DarkGray
    Write-Host "   Vuoi anche la SCANSIONE OFFLINE di Microsoft Defender?" -ForegroundColor White
    Write-Host "   Il PC si RIAVVIA subito in un ambiente speciale (circa 15 minuti)," -ForegroundColor Gray
    Write-Host "   dove un malware non puo' nascondersi perche' non e' in esecuzione." -ForegroundColor Gray
    Write-Host "   Salva e chiudi tutto prima di confermare." -ForegroundColor Yellow
    $r = Read-Host "   Scrivi RIAVVIA per avviarla, oppure INVIO per saltarla"
    if ($r -ceq 'RIAVVIA') {
        Write-Host "   Avvio la scansione offline: il PC si riavviera' tra pochi secondi." -ForegroundColor Cyan
        Start-MpWDOScan
    } else {
        Write-Host "   Scansione offline saltata." -ForegroundColor DarkGray
    }
}
# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDiICDBNnstobVq
# Vo1SQwNd7Ax6UitzgCbLpoHYi9qs86CCBCowggQmMIICjqADAgECAhBsFNOb1/0T
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDp2aPpLZgBkBYz
# qXIuRNN3kqO1pF798sjKZaR+VK0gsjANBgkqhkiG9w0BAQEFAASCAYBbsRkaVPJA
# DDAxKKH29KhhWRQTBFyQzZhBIIRZl0HJBElpPGxcdl1SSGZD3nrKszoxkr4Dy+32
# IP1qkVsO6U/FeR7nkXqJhddj4AJ9a2a0/djNOuE0y5ydg6uQdcYalXI2sFhvnd/u
# NUj/Jn5mSE8c2mqOcdhtfmQABRU5G+XJm0IO5C8teT7rvhlkuKZ/skkw3L0c9rk9
# 30KtZC0wl/QU0jt758/1wUOojKJKcIMDU1wW+OF6QKJZPuKuua46ziWnNEjD6/jD
# WiV7JGr8xqsi6Zpnp5FrFGCOdpKHzZuVzN2jH5bOG+E3JDk66qGGJEQydX/yq1Xk
# vDLnM5LmRduP3RrsnLuhc0TLWPLV3X3dDogilJKHjCd0fxM0y49hwamagFcBf6+e
# 7Zowhse3KJ6rp1KbvNE3szWBFw9O0Dqab4P5RX64X55fB1z9K5KYoqyGjlFsKC6C
# m7DBh4Pt/zBrsCu2+v4iWK/FWJnPz9iURxSCSgHAsNTuy5E9ygY7Hek=
# SIG # End signature block
