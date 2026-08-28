# Associa i file .p7m a CorianoSign per l'utente corrente (nessun admin).
#
#   powershell -ExecutionPolicy Bypass -File packaging\windows_associa_p7m.ps1
#   powershell ... -ExePath "C:\Percorso\CorianoSign.exe"
#   powershell ... -Remove        # rimuove l'associazione
#
# Nota: Windows 10/11 protegge la scelta predefinita (UserChoice). Questo script
# registra l'app; per renderla predefinita, la prima volta fai clic destro sul
# file .p7m -> "Apri con" -> "Scegli un'altra app" -> CorianoSign -> "Sempre".

param(
    [string]$ExePath = "",
    [switch]$Remove
)
$ErrorActionPreference = "Stop"

$ProgId = "CorianoSign.p7m"
$classes = "HKCU:\Software\Classes"

if ($Remove) {
    Remove-Item -Recurse -Force "$classes\$ProgId" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$classes\.p7m\OpenWithProgids" -ErrorAction SilentlyContinue
    Write-Host "Associazione CorianoSign rimossa."
    return
}

# individua l'eseguibile se non fornito
if (-not $ExePath) {
    $root = Join-Path $PSScriptRoot ".."
    $candidates = @(
        (Join-Path $root "dist\CorianoSign\CorianoSign.exe"),
        (Join-Path $root "dist\CorianoSign.exe")
    )
    foreach ($c in $candidates) { if (Test-Path $c) { $ExePath = (Resolve-Path $c).Path; break } }
}
if (-not $ExePath -or -not (Test-Path $ExePath)) {
    Write-Error "Eseguibile non trovato. Passa -ExePath 'C:\...\CorianoSign.exe'."
    return
}
$ExePath = (Resolve-Path $ExePath).Path
Write-Host "Eseguibile: $ExePath"

# ProgID: descrizione, icona, comando di apertura
New-Item -Force -Path "$classes\$ProgId" | Out-Null
Set-ItemProperty -Path "$classes\$ProgId" -Name "(default)" -Value "File firmato PKCS#7 (CAdES)"
New-Item -Force -Path "$classes\$ProgId\DefaultIcon" | Out-Null
Set-ItemProperty -Path "$classes\$ProgId\DefaultIcon" -Name "(default)" -Value "`"$ExePath`",0"
New-Item -Force -Path "$classes\$ProgId\shell\open\command" | Out-Null
Set-ItemProperty -Path "$classes\$ProgId\shell\open\command" -Name "(default)" -Value "`"$ExePath`" `"%1`""

# rende CorianoSign disponibile in "Apri con" per i .p7m
New-Item -Force -Path "$classes\.p7m\OpenWithProgids" | Out-Null
Set-ItemProperty -Path "$classes\.p7m\OpenWithProgids" -Name $ProgId -Value ([byte[]]@()) -Type Binary

# notifica alla shell il cambio di associazioni
$sig = '[System.Runtime.InteropServices.DllImport("shell32.dll")] public static extern void SHChangeNotify(int e, uint f, IntPtr a, IntPtr b);'
$t = Add-Type -MemberDefinition $sig -Name WinAPI -Namespace Shell -PassThru
$t::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)  # SHCNE_ASSOCCHANGED

Write-Host ""
Write-Host "Fatto. CorianoSign e' registrato per i file .p7m."
Write-Host "Per impostarlo come predefinito: clic destro su un .p7m ->"
Write-Host "'Apri con' -> 'Scegli un'altra app' -> CorianoSign -> spunta 'Sempre'."
