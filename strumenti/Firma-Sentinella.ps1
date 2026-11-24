# =====================================================================
#  Firma-Sentinella.ps1  -  per l'autore, non per chi usa Sentinella
#
#  Firma digitalmente sentinella.ps1 e i moduli, cosi' Sentinella puo'
#  accorgersi se qualcuno modifica i suoi file (controllo "Integrita'
#  di Sentinella"). Da rilanciare dopo ogni modifica al codice.
#
#  La prima volta crea un certificato personale di firma del codice nel
#  tuo archivio utente (Cert:\CurrentUser\My), con chiave NON esportabile.
#  Non lo aggiunge alle autorita' attendibili di Windows: non serve, e
#  non cambia nessuna impostazione di sicurezza del PC.
#
#  Uso:   powershell -NoProfile -ExecutionPolicy Bypass -File strumenti\Firma-Sentinella.ps1
# =====================================================================

$ErrorActionPreference = 'Stop'
$radice = Split-Path $PSScriptRoot -Parent
$soggetto = 'CN=Sentinella - firma codice (lozy)'

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Subject -eq $soggetto -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) {
    Write-Host "Creo il certificato di firma (valido 5 anni)..." -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $soggetto `
            -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 `
            -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(5)
}
Write-Host "Certificato: $($cert.Subject)  impronta $($cert.Thumbprint)  scade $($cert.NotAfter.ToString('dd/MM/yyyy'))"

# 1. L'impronta attesa va scritta PRIMA di firmare (la firma copre anche lei).
$fileIntegrita = Join-Path $radice 'moduli\Integrita.ps1'
$testo = [IO.File]::ReadAllText($fileIntegrita)
# Una firma precedente va tolta prima di modificare il file.
$testo = $testo -replace '(?s)\r?\n# SIG # Begin signature block.*$', ''
$testo = $testo -replace "(?m)^\`$improntaFirmaAttesa = '.*'", "`$improntaFirmaAttesa = '$($cert.Thumbprint)'"
[IO.File]::WriteAllText($fileIntegrita, $testo, (New-Object System.Text.UTF8Encoding $false))

# 2. Preparazione: prima di firmare, ogni file viene ripulito e controllato.
#    - la vecchia firma la togliamo noi: lasciarlo fare a Windows con fine
#      riga misti (LF dell'editor, CRLF della firma) gli fa tagliare anche
#      l'ultimo carattere del codice - e' successo: sparivano le '}' finali
#    - fine riga uniformati a CRLF, file che termina con un a capo
#    - il codice deve essere sintatticamente valido, o non si firma niente:
#      firmare un file rotto vorrebbe dire certificare un errore
$daFirmare = @(Join-Path $radice 'sentinella.ps1') + @(Get-ChildItem (Join-Path $radice 'moduli') -Filter *.ps1 | ForEach-Object { $_.FullName })
$rotti = 0
foreach ($f in $daFirmare) {
    $byte = [IO.File]::ReadAllBytes($f)
    $bom = ($byte.Length -ge 3 -and $byte[0] -eq 0xEF -and $byte[1] -eq 0xBB -and $byte[2] -eq 0xBF)
    $t = [IO.File]::ReadAllText($f)
    $t = $t -replace '(?s)(\r?\n)?# SIG # Begin signature block.*$', ''
    $t = ($t -replace "`r`n", "`n" -replace "`r", "`n").TrimEnd() -replace "`n", "`r`n"
    $t += "`r`n"
    [IO.File]::WriteAllText($f, $t, (New-Object System.Text.UTF8Encoding $bom))
    $tok = $null; $err = $null
    [void][Management.Automation.Language.Parser]::ParseInput($t, [ref]$tok, [ref]$err)
    if ($err.Count) {
        $rotti++
        Write-Host ("  {0,-22} NON VALIDO, riga {1}: {2}" -f (Split-Path $f -Leaf), $err[0].Extent.StartLineNumber, $err[0].Message) -ForegroundColor Red
    }
}
if ($rotti -gt 0) {
    Write-Host "Nessun file firmato: correggi gli errori qui sopra e rilancia." -ForegroundColor Red
    exit 1
}

# 3. Firma di tutti i file che Sentinella esegue.
foreach ($f in $daFirmare) {
    $r = Set-AuthenticodeSignature -FilePath $f -Certificate $cert -HashAlgorithm SHA256
    $esito = Get-AuthenticodeSignature -FilePath $f
    $ok = $esito.Status -in @('Valid', 'UnknownError') -and $esito.SignerCertificate.Thumbprint -eq $cert.Thumbprint
    $colore = 'Red'; if ($ok) { $colore = 'Green' }
    Write-Host ("  {0,-22} {1}" -f (Split-Path $f -Leaf), $(if ($ok) { 'firmato' } else { "ERRORE: $($esito.Status)" })) -ForegroundColor $colore
}
