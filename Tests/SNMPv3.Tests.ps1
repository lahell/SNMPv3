BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    Import-Module "$ProjectRoot\SNMPv3"
    $script:Credentials = Get-Content "$ProjectRoot\Tests\Credentials.json" -Raw | ConvertFrom-Json
}

Describe "SharpSnmpLib" {
    It "Should be latest version" {
        $CurrentSharpSnmpLibVersion = (Get-ChildItem -Path "$ProjectRoot\SNMPv3\lib\net*" -Filter 'SharpSnmpLib.dll' -Recurse)[0].VersionInfo.FileVersionRaw
        $LatestSharpSnmpLibVersion = [version](Find-Package *Lextm.SharpSnmpLib* -ProviderName 'NuGet' | Where-Object Name -eq 'Lextm.SharpSnmpLib').Version
        $LatestSharpSnmpLibVersion -gt $CurrentSharpSnmpLibVersion | Should -be $false
    }
}

Describe "ScriptAnalyzer" {
    It "Should return 0" {
        $Result = (Invoke-ScriptAnalyzer $ProjectRoot -Recurse).Count
        $Result | Should -Be 0
    }
}

Describe "Invoke-SNMPvSet -UserName <_.username> -AuthType <_.authtype> -PrivType <_.privtype>" -ForEach $script:Credentials {
    Context "Authentication and Privacy" {
        It "Should return 'SysName'" {
            $Request = @{
                UserName = $_.UserName
                AuthType = $_.AuthType
                AuthSecret = $_.AuthSecret
                PrivType = $_.PrivType
                PrivSecret = $_.PrivSecret
            }
            $Result = Invoke-SNMPv3Set @Request -Target demo.pysnmp.com -OID 1.3.6.1.2.1.1.5.0 -Type String -Value 'SysName'
            $Result.Value | Should -Be 'SysName'
        }
    }
}

Describe "Invoke-SNMPvGet -UserName <_.username> -AuthType <_.authtype> -PrivType <_.privtype>" -ForEach $Credentials {
    Context "Authentication and Privacy" {
        It "Should return 'SysName'" {
            $Request = @{
                UserName = $_.UserName
                AuthType = $_.AuthType
                AuthSecret = $_.AuthSecret
                PrivType = $_.PrivType
                PrivSecret = $_.PrivSecret
            }
            $Result = Invoke-SNMPv3Get @Request -Target demo.pysnmp.com -OID 1.3.6.1.2.1.1.5.0
            $Result.Value | Should -Be 'SysName'
        }
    }
}

Describe "Invoke-SNMPv3Walk -UserName <_.username> -AuthType <_.authtype> -PrivType <_.privtype>" -ForEach $Credentials {
    Context "Authentication and Privacy" {
        It "Should return 'SysName'" {
            $Request = @{
                UserName = $_.UserName
                AuthType = $_.AuthType
                AuthSecret = $_.AuthSecret
                PrivType = $_.PrivType
                PrivSecret = $_.PrivSecret
            }
            $Result = Invoke-SNMPv3Walk @Request -Target demo.pysnmp.com -OID 1.3.6.1.2.1.1.5
            $Result[0].Value | Should -Be 'SysName'
        }
    }
}
