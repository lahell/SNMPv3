if ($PSEdition -eq 'Core' -and $PSVersionTable.PSVersion -lt [version]::new(7, 2))
{
    throw 'This module requires PowerShell 7.2 or later'
}

if ($PSEdition -eq 'Core')
{
    $NetVersion = 'net6.0'
}
elseif ($PSEdition -eq 'Desktop')
{
    $NetVersion = 'net471'
}

Add-Type -LiteralPath "$PSScriptRoot\lib\$NetVersion\SharpSnmpLib.dll" | Out-Null

$Types = @( Get-ChildItem -Path $PSScriptRoot\Types\*.ps1 -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )
$Public = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue )

foreach ($Import in @($Types + $Private + $Public))
{
    try
    {
        . $Import.FullName
    }
    catch
    {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}

Export-ModuleMember -Function $Public.BaseName
