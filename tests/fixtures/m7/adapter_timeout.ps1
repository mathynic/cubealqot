[CmdletBinding()]
param(
    [string] $RequestFile,
    [string] $HelperFile,
    [string] $Distribution,
    [string] $CondaExecutable,
    [string] $Environment
)

Start-Sleep -Seconds 5
Write-Output '{"ok":true,"complete":true}'
