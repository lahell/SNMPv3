function Get-SNMPv3PrivacyProvider
{
    param(
        [string]$PrivType,
        [Lextm.SharpSnmpLib.OctetString]$PrivSecret,
        [Lextm.SharpSnmpLib.Security.IAuthenticationProvider]$Auth
    )
    
    switch ($PrivType)
    {
        'DES'
        { 
            [Lextm.SharpSnmpLib.Security.DESPrivacyProvider]::new($PrivSecret, $Auth)
        }

        'TripleDES'
        {
            [Lextm.SharpSnmpLib.Security.TripleDESPrivacyProvider]::new($PrivSecret, $Auth)
        }
        
        'AES128'
        {
            [Lextm.SharpSnmpLib.Security.AESPrivacyProvider]::new($PrivSecret, $Auth)
        }

        'AES192'
        {
            [Lextm.SharpSnmpLib.Security.AES192PrivacyProvider]::new($PrivSecret, $Auth)
        }

        'AES256'
        {
            [Lextm.SharpSnmpLib.Security.AES256PrivacyProvider]::new($PrivSecret, $Auth)
        }

        default
        {
            [Lextm.SharpSnmpLib.Security.DefaultPrivacyProvider]::new($Auth)
        }
    }
}
