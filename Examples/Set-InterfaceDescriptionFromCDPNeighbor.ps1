#Requires -Modules @{ ModuleName="SNMPv3"; ModuleVersion="1.1.1" }

# Prepare a hashtable with parameters
$Request = @{
    UserName   = 'MyUser'
    Target     = 'MySwitch'
    AuthType   = 'SHA1'
    AuthSecret = 'MyAuthSecret'
    PrivType   = 'AES256'
    PrivSecret = 'MyPrivSecret'
}

# Walk cdpCacheDeviceId
Invoke-SNMPv3Walk -OID 1.3.6.1.4.1.9.9.23.1.2.1.1.6 @Request | ForEach-Object {
    $Interface = $_.OID -split '\.' | Select-Object -SkipLast 1 | Select-Object -Last 1
    $OID = '{0}.{1}' -f '1.3.6.1.2.1.31.1.1.1.18', $Interface
    $Description = $_.Value -split '\.' | Select-Object -First 1

    # Set ifAlias
    Invoke-SNMPv3Set -OID $OID -Type String -Value $Description @Request
}
