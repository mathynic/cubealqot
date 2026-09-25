[CmdletBinding()]
param(
    [string] $RequestFile,
    [string] $HelperFile,
    [string] $Distribution,
    [string] $CondaExecutable,
    [string] $Environment
)

[Console]::Error.WriteLine('intentional fake backend failure')
exit 7
