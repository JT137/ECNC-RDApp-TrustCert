# ECNC one-line installer: irm https://raw.githubusercontent.com/JT137/ECNC-RDApp-TrustCert/main/install.ps1 | iex
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$p = Join-Path $env:TEMP 'RDApp-TrustCert-RefreshFeed.ps1'
Invoke-RestMethod 'https://raw.githubusercontent.com/JT137/ECNC-RDApp-TrustCert/main/RDApp-TrustCert-RefreshFeed.ps1' -OutFile $p
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p -FeedHost 'server-ecnc.ecnc.com'
