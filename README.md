# ECNC RDApp TrustCert

Trusts the RD Web feed certificate for the signed-in user and refreshes RemoteApp and Desktop Connections only when needed.

## Run (elevated, e.g. from RMM)

Replace `rd.example.com` with the feed host.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=\"$env:TEMP\RDApp-TrustCert-RefreshFeed.ps1\"; irm 'https://raw.githubusercontent.com/JT137/ECNC-RDApp-TrustCert/main/RDApp-TrustCert-RefreshFeed.ps1' -OutFile $p; & $p -FeedHost rd.example.com"
```

The script needs to run from a file (it copies itself to `C:\ProgramData\RdsScripts`), so it is downloaded first rather than piped to `iex`.
