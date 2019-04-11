function Get-SNMPv3SecurityLevel
{
    param(
        [string]$AuthType,
        [string]$AuthSecret,
        [string]$PrivType,
        [string]$PrivSecret
    )

    $Properties = @{}
    $Properties.Add('IsValid', $false)

    if ($AuthType -ne 'None' -and $AuthSecret -and $PrivType -ne 'None' -and $PrivSecret)
    {
        $Properties.Add('Level', 'authPriv')
        $Properties.IsValid = $true
    }
    elseif ($AuthType -ne 'None' -and $AuthSecret -and $PrivType -eq 'None' -and (-not $PrivSecret))
    {
        $Properties.Add('Level', 'authNoPriv')
        $Properties.IsValid = $true
    }
    elseif ($AuthType -eq 'None' -and (-not $AuthSecret) -and $PrivType -eq 'None' -and (-not $PrivSecret))
    {
        $Properties.Add('Level', 'noAuthNoPriv')
        $Properties.IsValid = $true
    }

    New-Object -TypeName PSObject -Property $Properties
}
