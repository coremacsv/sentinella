# =====================================================================
#  SENTINELLA - Parte D: confronto con l'ultima scansione
#  Una fotografia sola dice se qualcosa SEMBRA strano. Due fotografie
#  dicono cosa e' CAMBIATO, ed e' li' che si vede un'intrusione.
# =====================================================================

$etichetteImpronta = [ordered]@{
    'esclusioni' = 'esclusioni antivirus'
    'avvio'      = 'programmi in avvio automatico'
    'attivita'   = 'attivita pianificate'
    'servizi'    = 'servizi'
    'account'    = 'account e amministratori'
    'dns'        = 'server DNS'
    'hosts'      = 'righe nel file hosts'
    'programmi'  = 'programmi installati'
}
# Un cambiamento in queste tre categorie e' un campanello serio, non una nota.
$gravi3 = @('esclusioni', 'hosts', 'dns')
# Sale quando cambia cosa viene salvato nell'impronta: dalla 2 le attivita' includono i parametri.
$formatoImpronta = 2

function ImprontaSistema {
    $h = [ordered]@{}
    $avvio = @()
    foreach ($k in $script:chiaviAvvio) {
        $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($pr in $item.PSObject.Properties) {
            if ($script:proprietaPS -contains $pr.Name) { continue }
            $avvio += "$($pr.Name) = $($pr.Value)"
        }
    }
    foreach ($cart in $script:cartelleEsecuzioneAutomatica) {
        foreach ($x in (Get-ChildItem -LiteralPath $cart -File -ErrorAction SilentlyContinue)) { $avvio += "file: $($x.Name)" }
    }
    $h['avvio'] = @($avvio | Sort-Object)

    $tk = @()
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' })) {
        foreach ($a in $t.Actions) { if ($a.Execute) { $tk += "$($t.TaskName) -> $("$($a.Execute) $($a.Arguments)".Trim())" } }
    }
    $h['attivita'] = @($tk | Sort-Object)

    $sv = @()
    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        # I servizi "per utente" di Windows ricevono un codice casuale di 5
        # caratteri in coda al nome, rigenerato a ogni avvio: va tolto, o
        # ogni riavvio sembrerebbe aggiungere una ventina di servizi.
        $nomeStabile = $s.Name -replace '_[0-9a-f]{5}$', ''
        $sv += "$nomeStabile -> $($s.PathName)"
    }
    $h['servizi'] = @($sv | Sort-Object -Unique)

    $es = @()
    if ((Esiste 'Get-MpPreference') -and $script:admin) {
        $pf = Get-MpPreference -ErrorAction SilentlyContinue
        foreach ($v in $pf.ExclusionPath)      { if ($v -and $v -notlike 'N/A*') { $es += "cartella: $v" } }
        foreach ($v in $pf.ExclusionProcess)   { if ($v -and $v -notlike 'N/A*') { $es += "processo: $v" } }
        foreach ($v in $pf.ExclusionExtension) { if ($v -and $v -notlike 'N/A*') { $es += "estensione: $v" } }
    }
    $h['esclusioni'] = @($es | Sort-Object)

    $ac = @()
    if (Esiste 'Get-LocalUser') {
        foreach ($u in (Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled })) { $ac += $u.Name }
        try { foreach ($m in (Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544').Name -ErrorAction Stop)) { $ac += "admin: $($m.Name)" } } catch { }
    }
    $h['account'] = @($ac | Sort-Object)

    $dn = @()
    if (Esiste 'Get-DnsClientServerAddress') {
        foreach ($d in (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses })) {
            $dn += "$($d.InterfaceAlias): $($d.ServerAddresses -join ',')"
        }
    }
    $h['dns'] = @($dn | Sort-Object)

    $hs = @()
    foreach ($r in (Get-Content -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue)) {
        if ($r.Trim() -ne '' -and -not $r.Trim().StartsWith('#')) { $hs += $r.Trim() }
    }
    $h['hosts'] = @($hs | Sort-Object)

    $h['programmi'] = @(ProgrammiInstallati | ForEach-Object { $_.Nome } | Sort-Object -Unique)
    return $h
}

# Restituisce il motivo per cui una novita' non merita attenzione, o niente se la merita.
function MotivoTranquillo($categoria, $voce) {
    if ($categoria -notin @('avvio', 'attivita', 'servizi')) { return $null }
    $comando = ($voce -split ' (?:->|=) ', 2)[-1]
    if (ComandoPulizia $comando) { return "pulizia automatica lasciata da un programma" }
    if (ComandoSospetto $comando) { return $null }
    if (-not (FirmaValida $comando)) {
        $h = Impronta $comando
        if ($h -and $script:confermeFile.ContainsKey($h) -and $script:confermeFile[$h].risposta -eq 'si') { return "non firmato, riconosciuto da te" }
        return $null
    }
    $firma = NomeFirmatario $comando
    if ((EsuPercorsoSospetto $comando) -and $firma -notmatch '^Microsoft\b') { return $null }
    return "firmato da $firma"
}

function C_Confronto {
    $fileStato = Join-Path $script:cartellaDati 'ultima-scansione.json'
    $adesso = ImprontaSistema

    # Versione delle definizioni antivirus: un file fermo sul disco da mesi
    # puo' passare da "pulito" a "minaccia" senza essere cambiato, solo
    # perche' Defender ha imparato qualcosa di nuovo nel frattempo.
    $versioneDefAV = $null
    if (Esiste 'Get-MpComputerStatus') {
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mpStatus) { $versioneDefAV = $mpStatus.AntivirusSignatureVersion }
    }

    if (-not $script:admin) {
        # Senza amministratore mancano esclusioni e percorsi dei servizi: confrontarli darebbe
        # falsi "NUOVO", e salvarli rovinerebbe il confronto della prossima scansione.
        NonVerificato "Confronto saltato: serve l'amministratore, avvia SENTINELLA.bat"
        return
    }
    if (Test-Path -LiteralPath $fileStato) {
        try {
            $prec = Get-Content -LiteralPath $fileStato -Raw -ErrorAction Stop | ConvertFrom-Json
            $quando = [datetime]$prec.quando
            $gg = [math]::Round(((Get-Date) - $quando).TotalDays, 1)
            Nota "Ultima scansione: $($quando.ToString('dd/MM/yyyy HH:mm'))  ($gg giorni fa)"
            $cambiamenti = 0
            foreach ($chiave in $script:etichetteImpronta.Keys) {
                if ($chiave -eq 'attivita' -and $prec.formatoImpronta -ne $script:formatoImpronta) {
                    Nota "Attivita' pianificate: confronto ripreso dalla prossima scansione"
                    continue
                }
                $vecchi = @()
                if ($prec.impronta.$chiave) { $vecchi = @($prec.impronta.$chiave) }
                $nuovi = @($adesso[$chiave])
                $vecchiNorm = @($vecchi | ForEach-Object { SenzaVersione $_ })
                $nuoviNorm  = @($nuovi | ForEach-Object { SenzaVersione $_ })
                $aggiunti = @($nuovi | Where-Object { $vecchiNorm -notcontains (SenzaVersione $_) })
                $spariti  = @($vecchi | Where-Object { $nuoviNorm -notcontains (SenzaVersione $_) })
                foreach ($x in $aggiunti) {
                    $cambiamenti++
                    $testo = "NUOVO in $($script:etichetteImpronta[$chiave]): $x"
                    if ($chiave -eq 'programmi') {
                        $editore = (ProgrammiInstallati | Where-Object { $_.Nome -eq $x } | Select-Object -First 1).Editore
                        if ($editore) { $testo += " (editore dichiarato: $editore)" }
                    }
                    $tranquillo = MotivoTranquillo $chiave $x
                    if ($script:gravi3 -contains $chiave) { Allarme $testo }
                    elseif ($tranquillo) { Nota "   $testo  [$tranquillo]" }
                    else { Attenzione $testo }
                }
                foreach ($x in $spariti) {
                    $cambiamenti++
                    Nota "   rimosso da $($script:etichetteImpronta[$chiave]): $x"
                }
            }
            if ($cambiamenti -eq 0) { Ok "Nessun cambiamento: il sistema e' identico all'ultima scansione" }
            else {
                Ok "Confronto eseguito: $cambiamenti differenze (dettaglio qui sopra)"
                Nota "Se questi cambiamenti li hai fatti tu, va tutto bene. Altrimenti approfondisci."
            }
            if ($versioneDefAV -and $prec.versioneDefAV -and $prec.versioneDefAV -ne $versioneDefAV) {
                Nota "Definizioni antivirus cambiate dall'ultima scansione: $($prec.versioneDefAV) -> $versioneDefAV"
                Nota "Se oggi l'antivirus segnala qualcosa che ieri non vedeva, puo' essere per questo: ha imparato qualcosa di nuovo, non e' detto che il tuo PC sia cambiato."
            }
        } catch {
            NonVerificato "Impronta precedente illeggibile: la sostituisco con quella di oggi"
        }
    } else {
        Ok "Prima scansione: salvo l'impronta del sistema"
        Nota "Dal prossimo controllo Sentinella ti dira' esattamente cosa e' cambiato."
    }
    try {
        if (-not (Test-Path -LiteralPath $script:cartellaDati)) { New-Item -ItemType Directory -Path $script:cartellaDati -Force | Out-Null }
        @{ quando = (Get-Date).ToString('o'); impronta = $adesso; versioneDefAV = $versioneDefAV; formatoImpronta = $script:formatoImpronta } |
            ConvertTo-Json -Depth 6 | Out-File -FilePath $fileStato -Encoding utf8 -ErrorAction Stop
        Nota "Impronta aggiornata in $fileStato"
    } catch {
        NonVerificato "Non sono riuscito a salvare l'impronta per il prossimo confronto"
    }
}

# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC4D++8hwRmFTi4
# jNkwI8ohBbHlaQjPSvxRdn0ppu9YGaCCBCowggQmMIICjqADAgECAhBsFNOb1/0T
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDD31o1Y3tPwDUX
# n7wczME3J9w7b8OhV7CUxrIeIrrXQzANBgkqhkiG9w0BAQEFAASCAYBM5OJwytsj
# +xGhXqJM0hiG32LLL0JHlJzaKYpAedbLwjza7QG69sj5vv8co5sBqFrQimu1l26z
# LXfawQbwf7ter9kbDGGY3Og+mRv5DWs3LNZ/tp3zQ+GB9FDTo/jcZFNR8AdsfJ6E
# XneeCSHP3xZu/SsEHScnBZlKUWmvHcMVNXpBed3oVL+gdU0UY/bEeymUkv5QuGEJ
# IBg/FjBNsdWdkIEx/+BUG/g/mJ6ux5wgcEWO9N/w0rvkB6QVxGHN5y18xV5Z6Hih
# YmUMx2a0aGRrPD88ge7w4iTCmnCv5Z1MoE3xHRhCE4nEV54+2mA0DDKAZPeYijN4
# LHId3L0c5Imz//vxDj22noqcVd3g+YHmqRLJEWn2dtlIZ3z3JiZESPNaOzaHAaXE
# 5OIUlGxBEOiZ/HBcBWWCNBTGOXmcj9ZotSzBP0uZwqkwx9jFc0mn5A2h1IWxI/4+
# C2b9IzMyANi4fPU10nz1VLw91A0FvzMg/s12PZsAfD8cl3BqFuS89/0=
# SIG # End signature block
