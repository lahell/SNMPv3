function Get-SharpSnmpAuthenticationProvider
{
    param(
        [string]$AuthType,
        [Lextm.SharpSnmpLib.OctetString]$AuthSecret
    )

    switch ($AuthType)
    {
        'MD5'
        {
            [Lextm.SharpSnmpLib.Security.MD5AuthenticationProvider]::new($AuthSecret)
        }

        'SHA1'
        {
            [Lextm.SharpSnmpLib.Security.SHA1AuthenticationProvider]::new($AuthSecret)
        }

        'SHA256'
        {
            [Lextm.SharpSnmpLib.Security.SHA256AuthenticationProvider]::new($AuthSecret)
        }

        default
        {
            [Lextm.SharpSnmpLib.Security.DefaultAuthenticationProvider]::Instance
        }
    }
}