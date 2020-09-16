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
            if ([Lextm.SharpSnmpLib.Security.DESPrivacyProvider]::IsSupported) {
                [Lextm.SharpSnmpLib.Security.DESPrivacyProvider]::new($PrivSecret, $Auth)
            } else {
                [SNMPv3.BouncyCastle.BouncyCastleDESPrivacyProvider]::new($PrivSecret, $Auth)
            }
        }

        'TribleDES'
        {
            [Lextm.SharpSnmpLib.Security.TripleDESPrivacyProvider]::new($PrivSecret, $Auth)
        }
        
        'AES128'
        {
            if ([Lextm.SharpSnmpLib.Security.AESPrivacyProviderBase]::IsSupported) {
                [Lextm.SharpSnmpLib.Security.AESPrivacyProvider]::new($PrivSecret, $Auth)
            } else {
                [SNMPv3.BouncyCastle.BouncyCastleAESPrivacyProvider]::new($PrivSecret, $Auth)
            }
        }

        'AES192'
        {
            if ([Lextm.SharpSnmpLib.Security.AESPrivacyProviderBase]::IsSupported) {
                [Lextm.SharpSnmpLib.Security.AES192PrivacyProvider]::new($PrivSecret, $Auth)
            } else {
                [SNMPv3.BouncyCastle.BouncyCastleAES192PrivacyProvider]::new($PrivSecret, $Auth)
            }
        }

        'AES256'
        {
            if ([Lextm.SharpSnmpLib.Security.AESPrivacyProviderBase]::IsSupported) {
                [Lextm.SharpSnmpLib.Security.AES256PrivacyProvider]::new($PrivSecret, $Auth)
            } else {
                [SNMPv3.BouncyCastle.BouncyCastleAES256PrivacyProvider]::new($PrivSecret, $Auth)
            }
        }

        default
        {
            [Lextm.SharpSnmpLib.Security.DefaultPrivacyProvider]::new($Auth)
        }
    }
}
