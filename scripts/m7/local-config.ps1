function Get-M7CondaExecutable {
    param([Parameter(Mandatory = $true)][string] $CrateRoot)

    $key = 'CUBEALQOT_CONDA_EXECUTABLE'
    $environmentValue = [Environment]::GetEnvironmentVariable($key)
    if (-not [string]::IsNullOrWhiteSpace($environmentValue)) {
        return $environmentValue.Trim()
    }

    $configPath = Join-Path $CrateRoot '.env.local'
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        foreach ($line in Get-Content -LiteralPath $configPath) {
            if ($line -match '^\s*CUBEALQOT_CONDA_EXECUTABLE\s*=\s*(.*?)\s*$') {
                $value = $Matches[1].Trim().Trim('"').Trim("'")
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    return $value
                }
            }
        }
    }

    return 'conda'
}
