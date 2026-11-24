# =====================================================================
#  SENTINELLA - Integrita' di Sentinella stessa
#  Uno strumento che controlla se il PC e' stato manomesso deve prima di
#  tutto controllare di non essere stato manomesso lui. I file .ps1 sono
#  firmati digitalmente (strumenti\Firma-Sentinella.ps1): se qualcuno ne
#  cambia anche un solo carattere, la firma non corrisponde piu'.
#
#  Limite onesto: chi puo' modificare questi file puo' anche rifirmarli
#  con un proprio certificato, o cambiare l'impronta attesa qui sotto.
#  Il controllo ferma le modifiche accidentali e i malware generici, non
#  un attacco su misura contro Sentinella.
# =====================================================================

# Impronta del certificato con cui l'autore firma Sentinella.
# Aggiornata automaticamente da strumenti\Firma-Sentinella.ps1.
$improntaFirmaAttesa = '9347D833B909DA28799BB20AE8180AB08B973632'

function C_IntegritaSentinella {
    $file = @(Join-Path $script:cartellaSentinella 'sentinella.ps1') +
            @(Get-ChildItem -LiteralPath (Join-Path $script:cartellaSentinella 'moduli') -Filter '*.ps1' -File | ForEach-Object { $_.FullName })
    $firme = foreach ($f in $file) {
        $s = Get-AuthenticodeSignature -LiteralPath $f -ErrorAction SilentlyContinue
        [pscustomobject]@{ Nome = (Split-Path $f -Leaf); Stato = [string]$s.Status; Impronta = [string]$s.SignerCertificate.Thumbprint }
    }
    $nonFirmati = @($firme | Where-Object { $_.Stato -eq 'NotSigned' })
    if ($nonFirmati.Count -eq $firme.Count) {
        NonDisponibile "Copia di Sentinella non firmata (versione di sviluppo): integrita' non verificabile"
        return
    }
    $guai = 0
    foreach ($f in $firme) {
        if ($f.Stato -eq 'NotSigned') { $guai++; Allarme "Sentinella: $($f.Nome) NON e' firmato mentre gli altri file si': aggiunto o sostituito dopo la firma"; continue }
        if ($f.Stato -eq 'HashMismatch') { $guai++; Allarme "Sentinella: $($f.Nome) e' stato MODIFICATO dopo la firma"; continue }
        if ($script:improntaFirmaAttesa -and $f.Impronta -ne $script:improntaFirmaAttesa) { $guai++; Allarme "Sentinella: $($f.Nome) e' firmato da un certificato diverso da quello dell'autore"; continue }
        # 'UnknownError' = firma intatta, ma il certificato dell'autore non e'
        # tra quelli di cui Windows si fida (normale: e' un certificato personale).
        if ($f.Stato -notin @('Valid', 'UnknownError')) { $guai++; Attenzione "Sentinella: firma di $($f.Nome) in stato '$($f.Stato)'" }
    }
    if ($guai -eq 0) { Ok "I $($firme.Count) file di Sentinella sono integri (firma dell'autore verificata)" }
}

# SIG # Begin signature block
# MIIHRQYJKoZIhvcNAQcCoIIHNjCCBzICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAOYtcAzGK2wIDH
# udjhcvNllxxIGOq4gaDS/ndFn4+6+qCCBCowggQmMIICjqADAgECAhBsFNOb1/0T
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCcK5/mAQEBg3ZG
# TJpNfvi39WNJI4hb6bkkfHmkYyn6WzANBgkqhkiG9w0BAQEFAASCAYCZK1oRjDJI
# mvRC3/nZgxKLwhe15dwoWy36xPQH/pY38V/SXRsplcwRUfPSpnI9fqth3Uk7k0t9
# MNIFFBnytXjtDu6fBaTd3ZqeLGsCSW/1yI5VUC6LyQBjBa9KraoVbgMfkZ/DYB2m
# kKlQ7Yz6s7ZegKsrbA/Y0+9QG+sdkxUCuMbwNAYcpWiPhMlfg86sXTfEUsLdD1rQ
# 3T3U7xv4nLRQB/mjGyaw0jxkPiOAf2xuuwqKuheskAJuFaDlvJcw8OQAj/5aEcH7
# qZlhv/5jbfAwswZa8vzgdI0Czg6pXEeGDt7FLSrs4NpfYRqXe7mPJj8YLDtABGem
# NVRQ0Pc6LhULJZr368uBd4FUrMUY0tGIhSEqfo7fHK3g9N9pwGjwG/NyxjKuvAls
# I2NuHc5C2oA2An1zSbXeGkkt+4v8/gYgRhAM3cyRyC2WhMjMbbjvyst5E0VnSzE4
# Y+3xVvXdJPQR9VFXsxNkt9m0UaZrVhcruswmGexLGLPCBoH1I81iyOE=
# SIG # End signature block
