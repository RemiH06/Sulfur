<#
Registra la tarea programada "Sulfur respaldo", que corre respaldar.ps1 al
iniciar sesión y cada 4 horas. Si la máquina estaba dormida a la hora, corre
en cuanto despierta; si el destino está apagado, falla y lo intenta en la
siguiente vuelta. Solo sube cuando la bóveda cambió.

S4U: corre sin ventana y sin guardar tu contraseña de Windows. Si Windows
pide permisos de administrador para S4U, corre este script desde una terminal
elevada. Para quitarla: Unregister-ScheduledTask -TaskName "Sulfur respaldo"
El registro de cada vuelta queda en %LOCALAPPDATA%\sulfur\respaldo.log.
#>
$ErrorActionPreference = "Stop"
$script = Join-Path $PSScriptRoot "respaldar.ps1"
$usuario = "$env:COMPUTERNAME\$env:USERNAME"

$accion = New-ScheduledTaskAction -Execute (Get-Command pwsh).Source -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`""
$alEntrar = New-ScheduledTaskTrigger -AtLogOn -User $usuario
$cada4h = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddHours(9) -RepetitionInterval (New-TimeSpan -Hours 4)
$ajustes = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew
$quien = New-ScheduledTaskPrincipal -UserId $usuario -LogonType S4U

Register-ScheduledTask -TaskName "Sulfur respaldo" -Description "Copia la bóveda cifrada de Sulfur a Pixilate ($script)" -Action $accion -Trigger $alEntrar, $cada4h -Settings $ajustes -Principal $quien -Force |
    Select-Object TaskName, State
