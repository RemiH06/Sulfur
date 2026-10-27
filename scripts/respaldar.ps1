<#
Copia la bóveda de Sulfur a otra máquina por SSH, con fecha en el nombre.

La bóveda va cifrada, así que el destino solo ve cuántas entradas hay y su
tamaño en bloques de 256 bytes. Sube solo si cambió desde el último respaldo,
verifica el SHA-256 en el destino antes de darla por buena y conserva las
últimas $Conservar copias. Las copias viejas abren con la maestra que tenían:
después de `sulfur passwd`, borra las anteriores si cambiaste la maestra
porque se filtró.

El destino es un alias de ~/.ssh/config cuyo shell remoto es PowerShell.
Sale con código 0 si respaldó o no había cambios, y 1 si falló.
#>
param(
    [string]$Destino = "pixilate",
    [string]$Carpeta = "respaldos\sulfur",
    [int]$Conservar = 30
)

$ErrorActionPreference = "Stop"
$log = Join-Path $env:LOCALAPPDATA "sulfur\respaldo.log"
New-Item -ItemType Directory -Force (Split-Path $log) | Out-Null

function Registrar([string]$mensaje) {
    $linea = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $mensaje"
    Write-Output $linea
    Add-Content -Path $log -Value $linea -Encoding utf8
}

# Corre un comando de PowerShell en el destino y devuelve su salida.
function Remoto([string]$comando) {
    $salida = ssh -o BatchMode=yes -o ConnectTimeout=15 $Destino $comando
    if ($LASTEXITCODE -ne 0) { throw "ssh $Destino salió con código $LASTEXITCODE" }
    $salida
}

try {
    $boveda = if ($env:SULFUR_VAULT) { $env:SULFUR_VAULT } else { Join-Path $env:APPDATA "sulfur\vault.json" }
    if (-not (Test-Path -LiteralPath $boveda)) { throw "no existe la bóveda $boveda" }

    # Se copia a un temporal local primero: si sulfur guarda a media subida,
    # el hash y lo subido siguen siendo del mismo archivo.
    $copia = Join-Path ([IO.Path]::GetTempPath()) ("sulfur-respaldo-" + [guid]::NewGuid() + ".json")
    Copy-Item -LiteralPath $boveda $copia
    try {
        $hash = (Get-FileHash -LiteralPath $copia -Algorithm SHA256).Hash

        $ultimo = Remoto "New-Item -ItemType Directory -Force $Carpeta | Out-Null; Get-ChildItem $Carpeta -Filter *.json | Sort-Object Name | Select-Object -Last 1 | Get-FileHash -Algorithm SHA256 | ForEach-Object Hash"
        if ($ultimo -eq $hash) {
            Registrar "sin cambios desde el último respaldo en $Destino"
            exit 0
        }

        $base = [IO.Path]::GetFileNameWithoutExtension($boveda)
        $nombre = "$base-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $remoto = "$Carpeta\$nombre"
        scp -q -o BatchMode=yes -o ConnectTimeout=15 $copia "${Destino}:$($remoto -replace '\\', '/').part"
        if ($LASTEXITCODE -ne 0) { throw "scp salió con código $LASTEXITCODE" }

        $verificado = Remoto "if ((Get-FileHash -Algorithm SHA256 '$remoto.part').Hash -eq '$hash') { Move-Item '$remoto.part' '$remoto'; 'ok' } else { Remove-Item '$remoto.part'; 'distinto' }"
        if ($verificado -ne "ok") { throw "el hash en $Destino no coincide; se borró la copia" }

        $borradas = Remoto "Get-ChildItem $Carpeta -Filter *.json | Sort-Object Name -Descending | Select-Object -Skip $Conservar | ForEach-Object { Remove-Item `$_.FullName; `$_.Name }"
        Registrar ("respaldada en ${Destino}:$remoto" + $(if ($borradas) { "; borradas: $($borradas -join ', ')" } else { "" }))
    }
    finally {
        Remove-Item -LiteralPath $copia -ErrorAction SilentlyContinue
    }
}
catch {
    Registrar "falló: $($_.Exception.Message)"
    exit 1
}
