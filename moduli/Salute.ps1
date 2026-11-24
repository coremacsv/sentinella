# =====================================================================
#  SENTINELLA - Parte B: salute del PC
# =====================================================================

function C_Spazio {
    if (-not $script:dischi -or @($script:dischi).Count -eq 0) { NonVerificato "Nessun disco rilevato"; return }
    foreach ($v in $script:dischi) {
        $tot = [math]::Round($v.Size/1GB,1)
        $lib = [math]::Round($v.SizeRemaining/1GB,1)
        $pct = 0
        if ($v.Size -gt 0) { $pct = [math]::Round(($v.SizeRemaining/$v.Size)*100,1) }
        $et = "$($v.DriveLetter): $lib GB liberi su $tot GB ($pct%)"
        if ($pct -lt 5)      { Problema "SPAZIO QUASI ESAURITO - $et - Windows puo' diventare instabile" }
        elseif ($pct -lt 12) { Avviso "Spazio in esaurimento - $et" }
        else                 { Ok $et }
        if ($v.HealthStatus -and $v.HealthStatus -ne 'Healthy') { Problema "Volume $($v.DriveLetter): stato $($v.HealthStatus)" }
    }
}

function C_Smart {
    if (-not (Esiste 'Get-PhysicalDisk')) { NonDisponibile "Diagnostica dischi non disponibile su questo sistema"; return }
    $fisici = Leggi { Get-PhysicalDisk } "Dischi fisici"
    if ($null -eq $fisici) { return }
    if ($fisici.Count -eq 0) { NonVerificato "Windows non ha restituito nessun disco fisico"; return }
    foreach ($d in $fisici) {
        $riga = "$($d.FriendlyName) [$($d.MediaType)] - stato: $($d.HealthStatus)"
        if ($d.HealthStatus -ne 'Healthy') { Problema "DISCO IN SOFFERENZA: $riga - fai subito una copia dei dati" }
        else { Ok $riga }
        $rc = Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue
        if (-not $rc) { NonVerificato "$($d.FriendlyName): contatori di usura non leggibili"; continue }
        if ($null -ne $rc.Wear -and $rc.Wear -gt 80)              { Avviso "$($d.FriendlyName): usura al $($rc.Wear)% (SSD verso fine vita)" }
        if ($null -ne $rc.Temperature -and $rc.Temperature -gt 60) { Avviso "$($d.FriendlyName): temperatura $($rc.Temperature) gradi" }
        if ($rc.ReadErrorsUncorrected -gt 0)  { Problema "$($d.FriendlyName): $($rc.ReadErrorsUncorrected) errori di lettura non corretti" }
        if ($rc.WriteErrorsUncorrected -gt 0) { Problema "$($d.FriendlyName): $($rc.WriteErrorsUncorrected) errori di scrittura non corretti" }
        if ($null -ne $rc.PowerOnHours) {
            # Un disco consumer e' garantito per 3-5 anni di uso continuo
            # (26.000-44.000 ore): oltre 50.000 vale la pena un backup extra.
            if ($rc.PowerOnHours -gt 50000) { Avviso "   $($d.FriendlyName): $($rc.PowerOnHours) ore di accensione - oltre la vita utile tipica, considera un backup extra" }
            else { Nota "   ore di accensione totali: $($rc.PowerOnHours)" }
        }
    }
}

function C_Memoria {
    $os = $script:os
    if (-not $os -or -not $os.TotalVisibleMemorySize) { NonVerificato "Dati sulla memoria non leggibili"; return }
    $totGB = [math]::Round($os.TotalVisibleMemorySize/1MB,1)
    $libGB = [math]::Round($os.FreePhysicalMemory/1MB,1)
    $usoPct = [math]::Round((1 - ($os.FreePhysicalMemory/$os.TotalVisibleMemorySize))*100,1)
    Nota "RAM totale $totGB GB - libera $libGB GB - in uso $usoPct%"
    if ($usoPct -gt 92) { Avviso "Memoria quasi satura ($usoPct%): il PC rallenta" } else { Ok "Uso della memoria nella norma" }
    Nota "I 5 processi piu' pesanti:"
    foreach ($p in (Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5)) {
        Nota ("   {0,-30} {1,8:N0} MB" -f $p.ProcessName, ($p.WorkingSet64/1MB))
    }
}

function C_ErroriSistema {
    $ev = LeggiEventi @{ LogName = 'System'; Level = 1, 2; StartTime = $script:da } "Registro di sistema"
    if ($null -eq $ev) { return }
    if ($ev.Count -eq 0) { Ok "Nessun errore critico registrato negli ultimi $($script:giorniLog) giorni" }
    else {
        Nota "$($ev.Count) eventi di errore o critici. Per origine:"
        foreach ($g in ($ev | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 8)) {
            Nota ("   {0,-40} {1,4}" -f $g.Name, $g.Count)
        }
        $bsod = @($ev | Where-Object { $_.Id -eq 1001 -and $_.ProviderName -match 'WER-SystemErrorReporting|BugCheck' })
        if ($bsod.Count -gt 0) {
            $codice = [regex]::Match([string]$bsod[0].Message, '0x[0-9a-fA-F]{8}').Value
            $testoBsod = "Schermate blu registrate: $($bsod.Count) (ultimo codice: $codice, del $($bsod[0].TimeCreated.ToString('dd/MM/yyyy HH:mm')))"
            if ($bsod.Count -ge 3) { Problema $testoBsod } else { Avviso $testoBsod }
        }
        $disco = @($ev | Where-Object { $_.ProviderName -match '^disk$|Ntfs|storahci|stornvme' })
        if ($disco.Count -gt 0) { Problema "$($disco.Count) errori di disco o file system: possibile disco in sofferenza" }
        $dcom = @($ev | Where-Object { $_.ProviderName -like '*DistributedCOM*' })
        if ($dcom.Count -gt 0) { Nota "   (di cui $($dcom.Count) DistributedCOM: quasi sempre innocui)" }
        if ($bsod.Count -eq 0 -and $disco.Count -eq 0) { Ok "Nessuna schermata blu e nessun errore del disco" }
    }

    # Blocchi temporanei (LiveKernelEvent): Windows li ripresenta a ogni
    # tentativo di invio, quindi si contano per nome del file di dump.
    $wer = LeggiEventi @{ LogName = 'Application'; ProviderName = 'Windows Error Reporting'; Id = 1001; StartTime = $script:da } "Segnalazioni errori di Windows"
    if ($null -eq $wer) { return }
    $blocchi = @{}
    foreach ($e in $wer) {
        $msg = [string]$e.Message
        $codice = [regex]::Match($msg, '(?m)^P1:\s*([0-9A-Fa-f]+)').Groups[1].Value
        foreach ($m in [regex]::Matches($msg, 'WATCHDOG\d*-(\d{8})-(\d{4})\.dmp')) {
            try {
                $q = [datetime]::ParseExact($m.Groups[1].Value + $m.Groups[2].Value, 'yyyyMMddHHmm', $null)
                if ($q -ge $script:da) { $blocchi[$q] = (OrigineBlocco $codice) }
            } catch { }
        }
    }
    if ($blocchi.Count -gt 0) {
        $video = @($blocchi.Keys | Where-Object { $blocchi[$_] -eq 'scheda video' } | Sort-Object -Descending)
        $altri = $blocchi.Count - $video.Count
        $date = ($blocchi.Keys | Sort-Object -Descending | Select-Object -First 5 | ForEach-Object { $_.ToString('dd/MM HH:mm') }) -join ', '
        $chi = 'componenti di sistema'
        if ($video.Count -eq $blocchi.Count) { $chi = 'tutti della scheda video o del suo driver' }
        elseif ($video.Count -gt 0) { $chi = "$($video.Count) della scheda video, $altri di altri componenti" }
        $testo = "$($blocchi.Count) blocchi temporanei superati da soli ($chi) - ultimi: $date"
        if ($blocchi.Count -ge 3) {
            Avviso $testo
            SpiegaDinamica `
                "Windows ha rilevato piu' volte un componente bloccato ($chi) e l'ha fatto ripartire da solo. Si vedono come scatti, schermo nero per un attimo o un gioco che si chiude." `
                "Aggiorna il driver della scheda video dal sito del produttore (AMD, NVIDIA, Intel). Se hai fatto overclock o undervolt della scheda video, riportala ai valori di fabbrica e vedi se i blocchi spariscono."
        } else { Nota $testo }
    }
}

function C_ErroriHardware {
    # Errori che l'hardware stesso dichiara di non aver potuto correggere.
    # Rari per natura: si guarda un periodo lungo (90 giorni), e il titolo
    # del controllo lo dice (nella v2 stavano sotto "ultimi 7/30 giorni").
    $inizio = (Get-Date).AddDays(-90)
    $whea = LeggiEventi @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $inizio } "Errori hardware (WHEA)"
    if ($null -eq $whea) { return }
    $riavvii = LeggiEventi @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $inizio } "Spegnimenti improvvisi"
    if ($null -eq $riavvii) { $riavvii = @() }

    $gravi = @($whea | Where-Object { $_.Level -in 1, 2 })
    $corretti = @($whea | Where-Object { $_.Level -eq 3 })
    $errori = foreach ($e in $gravi) {
        $dati = @{}
        try { foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { $dati[$d.Name] = $d.'#text' } } catch { }
        [pscustomobject]@{ Tempo = $e.TimeCreated; ApicId = $dati['ApicId']; Banco = $dati['MCABank'] }
    }
    $smt = $false
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cpu -and $cpu.NumberOfLogicalProcessors -gt $cpu.NumberOfCores) { $smt = $true }
    $a = AnalizzaWhea $errori ($riavvii | ForEach-Object { $_.TimeCreated }) $smt

    if ($a.Totale -gt 0) {
        $date = ($gravi | Select-Object -First 5 | ForEach-Object { $_.TimeCreated.ToString('dd/MM/yyyy HH:mm') }) -join ', '
        Problema "$($a.Totale) errori hardware irreversibili negli ultimi 90 giorni, $($a.ConRiavvio) seguiti da un riavvio improvviso - date: $date"
        switch ($a.Diagnosi) {
            'stesso-core' {
                Nota "   Sempre dallo stesso core del processore (core $($a.Core[0]))."
                SpiegaDinamica `
                    "Il processore ha segnalato $($a.Totale) volte un errore che non ha potuto correggere, e $($a.ConRiavvio) volte il PC si e' riavviato da solo subito dopo. Viene sempre dallo stesso core: quel core e' piu' debole degli altri, oppure e' spinto oltre il suo limite (undervolt per singolo core, Curve Optimizer, overclock)." `
                    "Se hai impostato Curve Optimizer o un undervolt, riporta QUEL core (numero $($a.Core[0])) a 0 o a un valore meno spinto. Se tutto e' gia' ai valori di fabbrica e succede ancora, il processore va fatto controllare in garanzia."
            }
            'core-diversi' {
                Nota "   Da core diversi del processore ($($a.Core -join ', ')): non e' un singolo core difettoso."
                SpiegaDinamica `
                    "Il processore ha segnalato $($a.Totale) volte un errore che non ha potuto correggere, e $($a.ConRiavvio) volte il PC si e' riavviato da solo subito dopo. Ogni volta da un core diverso ($($a.Core -join ', ')): quando il problema non sta in un core preciso, la causa e' quasi sempre in cio' che i core condividono - il collegamento con la RAM, le tensioni, o il risparmio energetico a riposo. Non e' un virus." `
                    "Nel BIOS, una prova alla volta: 1) imposta 'Power Supply Idle Control' su 'Typical Current Idle' (risolve molti riavvii a riposo sui Ryzen); 2) se continua, abbassa la RAM di un gradino (es. da 3600 a 3466) o disattiva il profilo XMP/EXPO; 3) aggiorna il BIOS. Se succede anche con tutto ai valori di fabbrica, fai controllare processore e alimentatore."
            }
            default {
                SpiegaDinamica `
                    "Un componente hardware ha segnalato un errore che non ha potuto correggere: e' un guasto o un'instabilita' dell'hardware, non un virus, e di solito provoca un riavvio improvviso." `
                    "Salva i file importanti. Poi: controlla nel BIOS che overclock, PBO o Curve Optimizer siano disattivati, aggiorna il BIOS, e prova il PC con un test di stabilita'. Se gli errori continuano con tutto ai valori di fabbrica, il pezzo va fatto controllare."
            }
        }
    } else { Ok "Nessun errore hardware irreversibile negli ultimi 90 giorni" }
    if ($corretti.Count -gt 0) { Nota "   $($corretti.Count) errori hardware corretti automaticamente (avvisi, di solito innocui se rari)" }

    # Spegnimenti improvvisi NON spiegati da un errore hardware: mancanza di
    # corrente, pulsante tenuto premuto, o un blocco totale.
    $senzaCausa = @($riavvii | Where-Object {
        $t = $_.TimeCreated
        -not ($gravi | Where-Object { [Math]::Abs(($_.TimeCreated - $t).TotalSeconds) -le 120 })
    })
    if ($senzaCausa.Count -gt 0) {
        $date = ($senzaCausa | Select-Object -First 5 | ForEach-Object { $_.TimeCreated.ToString('dd/MM HH:mm') }) -join ', '
        $testo = "$($senzaCausa.Count) spegnimenti improvvisi senza errore hardware (corrente, pulsante di accensione, blocco) - ultimi: $date"
        if ($senzaCausa.Count -ge 3) { Avviso $testo } else { Nota "   $testo" }
    }
}

function C_Crash {
    $cartella = "$env:SystemRoot\Minidump"
    if (-not (Test-Path -LiteralPath $cartella)) { Ok "Nessun file di crash"; return }
    $mini = Leggi { Get-ChildItem -LiteralPath $cartella -Filter *.dmp } "Cartella dei crash"
    if ($null -eq $mini) { return }
    if ($mini.Count -eq 0) { Ok "Nessun file di crash"; return }
    $ultimo = ($mini | Sort-Object LastWriteTime -Descending)[0]
    $testoMini = "$($mini.Count) file di crash presenti. Ultimo: $($ultimo.LastWriteTime.ToString('dd/MM/yyyy HH:mm'))"
    if ($ultimo.LastWriteTime -ge (Get-Date).AddDays(-30)) {
        Avviso $testoMini
        Nota "   Indicano schermate blu passate: spesso driver o memoria RAM difettosa."
    } else { Nota "$testoMini (piu' di 30 giorni fa)"; Ok "Nessuna schermata blu negli ultimi 30 giorni" }
}

function C_Periferiche {
    $ko = Leggi { Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object { $null -ne $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 } } "Elenco periferiche"
    if ($null -eq $ko) { return }
    $problemi = 0
    foreach ($k in ($ko | Select-Object -First 10)) {
        $codice = [int]$k.ConfigManagerErrorCode
        $nome = NomePeriferica $k
        $perche = SpiegaCodicePeriferica $codice
        # 22 = disattivata a mano, 45 = scollegata: non sono guasti.
        if ($codice -in 22, 45) { Nota "   $nome - $perche"; continue }
        $problemi++
        Avviso "Periferica con problemi: $nome - $perche (codice $codice)"
    }
    if ($problemi -eq 0) { Ok "Nessuna periferica in errore" }
}

function C_Aggiornamenti {
    $hot = Leggi { Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1 } "Storico aggiornamenti"
    if ($null -ne $hot) {
        if ($hot.Count -gt 0) {
            $gg = [math]::Round(((Get-Date) - $hot[0].InstalledOn).TotalDays)
            Nota "Ultimo aggiornamento: $($hot[0].HotFixID) del $($hot[0].InstalledOn.ToString('dd/MM/yyyy')) ($gg giorni fa)"
            if ($gg -gt 60) { Avviso "Windows non riceve aggiornamenti da $gg giorni: mancano correzioni di sicurezza" }
            else { Ok "Aggiornamenti recenti" }
        } else { NonVerificato "Storico aggiornamenti vuoto" }
    }
    $riavvio = $false
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                     'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
        if (Test-Path $k) { $riavvio = $true }
    }
    if ($riavvio) { Avviso "C'e' un riavvio in sospeso: alcuni aggiornamenti non sono ancora completi" }
    else { Ok "Nessun riavvio in sospeso" }
}

function C_ProgrammiRecenti {
    $rec = @(ProgrammiInstallati | Where-Object { $_.Data -and $_.Data -ge (Get-Date).AddDays(-30) })
    if ($rec.Count -eq 0) { Ok "Nessun programma installato negli ultimi 30 giorni"; return }
    $senzaFirma = 0
    foreach ($x in ($rec | Sort-Object Data -Descending | Select-Object -First 25)) {
        $percorsoExe = TrovaEseguibileInstallato $x
        if (-not $percorsoExe) { Nota ("   {0:dd/MM/yyyy}  {1}" -f $x.Data, $x.Nome); continue }
        if (FirmaValida $percorsoExe) { Nota ("   {0:dd/MM/yyyy}  {1}  -  firmato da {2}" -f $x.Data, $x.Nome, (NomeFirmatario $percorsoExe)); continue }
        $noto = ComponenteNoto $x.Nome
        if ($noto) { Nota ("   {0:dd/MM/yyyy}  {1}  -  non firmato, ma conosciuto: {2}" -f $x.Data, $x.Nome, $noto); continue }
        if ($script:conferme.ContainsKey($x.Nome) -and $script:conferme[$x.Nome].risposta -eq 'si') {
            Nota ("   {0:dd/MM/yyyy}  {1}  -  non firmato, ma confermato da te il {2}" -f $x.Data, $x.Nome, $script:conferme[$x.Nome].quando); continue
        }
        if ($script:conferme.ContainsKey($x.Nome) -and $script:conferme[$x.Nome].risposta -eq 'no') {
            $senzaFirma++
            Attenzione ("{0:dd/MM/yyyy}  {1}  -  NON firmato digitalmente, gia' segnalato come non riconosciuto il {2}" -f $x.Data, $x.Nome, $script:conferme[$x.Nome].quando); continue
        }
        # Nessuna domanda qui: finisce nella lista unica di fine scansione.
        $senzaFirma++
        $t = "{0:dd/MM/yyyy}  {1}  -  NON firmato digitalmente" -f $x.Data, $x.Nome
        Attenzione $t
        $ed = ''; if ($x.Editore) { $ed = ", editore dichiarato: $($x.Editore)" }
        ProponiConferma 'programma' "programma:$($x.Nome)" $x.Nome ("programma installato il {0:dd/MM/yyyy}{1}" -f $x.Data, $ed) 1 $t
    }
    if ($rec.Count -gt 25) { Nota "Altri $($rec.Count - 25) programmi recenti non controllati: l'elenco mostra solo i 25 piu' nuovi." }
    if ($senzaFirma -eq 0) { Ok "$($rec.Count) programmi installati di recente, nessuno sconosciuto e senza firma" }
    else { Nota "$senzaFirma senza firma digitale (segnalati sopra): non e' detto siano un problema, ma sono quelli su cui vale la pena essere sicuri di averli installati tu." }
}
function TrovaEseguibileInstallato($x) {
    if ($x.Icona) {
        $p = ([string]$x.Icona -replace ',-?\d+$', '').Trim('"')
        if ($p -match '(?i)\.exe$' -and (Test-Path -LiteralPath $p)) { return $p }
    }
    if ($x.Loc -and (Test-Path -LiteralPath $x.Loc)) {
        $exe = Get-ChildItem -LiteralPath $x.Loc -Filter '*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($exe) { return $exe.FullName }
    }
    return $null
}

function C_Integrita {
    if (-not $script:completa) { NonDisponibile "Saltata: e' inclusa solo nella scansione completa (richiede minuti)"; return }
    if (-not $script:admin) { NonVerificato "La verifica dei file di sistema richiede l'amministratore"; return }
    $tmpSfc = Join-Path $env:TEMP 'sentinella-sfc.txt'
    $procSfc = Start-Process -FilePath "$env:SystemRoot\System32\sfc.exe" -ArgumentList '/verifyonly' `
               -RedirectStandardOutput $tmpSfc -NoNewWindow -PassThru
    AttendiProcesso $procSfc "verifica dei file di sistema"
    # sfc scrive in UTF-16: letto come testo normale uscirebbe illeggibile.
    $sfc = (Get-Content -LiteralPath $tmpSfc -Encoding Unicode -Raw) -replace "`0", ''
    Remove-Item -LiteralPath $tmpSfc -Force -ErrorAction SilentlyContinue
    # La frase esatta cambia tra versioni di Windows: si cercano parole chiave stabili.
    $sfcPulito = ($sfc -match 'did not find any integrity violations') -or ($sfc -match 'nessuna violazione')
    $sfcRotto  = $sfc -match 'violazion|integrity violation|found corrupt|danneggiat'
    if ($sfcPulito)     { Ok "File di sistema integri" }
    elseif ($sfcRotto)  { Problema "File di sistema danneggiati. Riparabili con: sfc /scannow (da amministratore)" }
    else                { NonVerificato "Esito della verifica non interpretabile: non considerarla superata" }
}

# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAFfHrYy/wSRw+V
# 6I5o9VvVZ6WCSSEtcPZmjT436AauLKCCBCowggQmMIICjqADAgECAhBsFNOb1/0T
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAh3OM6MoE4j5If
# 89sAUKnmGxO+XnV/DhqqJBy49h4s4TANBgkqhkiG9w0BAQEFAASCAYBFj1kRJ7PN
# GUkUscpCLVNwTjogGc6Zj4/rCkCzNC3cQFNJqy1OTl27HuKc31RMiJaIrsg1eSSN
# SpqNWkp7299dT/2r2zJ7aRgGqYe4S5oisLVCGaiV9eJUoU8oH9dDrzKuzP7Y4f+S
# suTG9cLaiA6fjCHcz6L/hMJD8CIExvRvMiPD5ANJjtqihIbaT0liV9tpzATxWKDq
# 2jMpaX6sGuHhsq1kqb0nCDPrX91n8R9jttOHaKwqt1GGdJX+xQ0v89VdwIt2xb0D
# ntsumyTfcVrsTvJ2JZPN2K6qmk5Wkm2dcGIGz0+C4zz7BXDflHLZKCSQbnODtnLq
# RBOAOTpFjpl9Na+DsgZJ57gpCsJ/Vp3rmLmpz5+Fmg8dg2i/dbidHMeUELQ1vd/Y
# JVjyqKXggBEpgewyZHOpmi+V+wT4DIMYpd/qDDu+4rt3D3psrEoWOJP/vaIjnplW
# LCN6Jdkp5zKvSUUxzLbkgIBNAz6pEzVDA1/jMHYfXuaIvtljdupJGlA=
# SIG # End signature block
