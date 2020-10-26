function Invoke-SNMPv3Walk
{

<#

.SYNOPSIS

    Query information from network devices using SNMP GETNEXT requests.

.DESCRIPTION

    Function supports SNMPv3 with security levels noAuthNoPriv, authNoPriv and authPriv.
    Based on SnmpSharpNet - SNMP Library for C# (http://www.snmpsharpnet.com/) 

.PARAMETER UserName

    Username to use when polling information.

.PARAMETER Target

    SNMP Agent you want to get information from. Accepts IP address or host name.

.PARAMETER OID

    GETNEXT requests will start at this object identifier and get all results from the subtree.
    Note that no value will be returned for the provided OID, only from the subtree.

.PARAMETER AuthType

    Allowed authentication types are None, MD5, SHA1 and SHA256. Defaults to None.

.PARAMETER AuthSecret

    Authentication password used for security level authNoPriv and authPriv.

.PARAMETER PrivType

    Allowed encryption types are None, DES, TripleDES, AES128, AES192 and AES256. Defaults to None.

.PARAMETER PrivSecret

    Encryption password used for security level authPriv.

.PARAMETER Context

    Context to use. For example to request information in the context of a specific vlan.

.PARAMETER Port

    UDP port to use when connecting to the SNMP Agent. Defaults to 161.

.PARAMETER Timeout

    Timeout in milliseconds when connecting to SNMP Agent. Defaults to 3000.

.INPUTS

    None. You cannot pipe objects to SNMPv3Walk.

.OUTPUTS

    SNMPv3Output

.EXAMPLE

    PS> Invoke-SNMPv3Walk -UserName usr-none-none -Target demo.snmplabs.com -OID 1.3.6.1.2.1.2.2.1.1 -Context 1016117d6836664ee15b9b2af5642c3c

    Node           OID                        Type Value
    ----           ---                        ---- -----
    104.236.166.95 1.3.6.1.2.1.2.2.1.1.1 Integer32 1    
    104.236.166.95 1.3.6.1.2.1.2.2.1.1.2 Integer32 2    
    104.236.166.95 1.3.6.1.2.1.2.2.1.1.3 Integer32 3    
    104.236.166.95 1.3.6.1.2.1.2.2.1.1.4 Integer32 4    
    104.236.166.95 1.3.6.1.2.1.2.2.1.1.5 Integer32 5 

#>

    [CmdletBinding()]
    [OutputType('SNMPv3Output')]
    param(
        [Parameter(Mandatory=$true)]
        [String]$UserName,

        [Parameter(Mandatory=$true)]
        [String]$Target,

        [Parameter(Mandatory=$true)]
        [String]$OID,

        [Parameter(Mandatory=$false)]
        [SNMPv3AuthType]$AuthType = 'None',

        [Parameter(Mandatory=$false)]
        [String]$AuthSecret,

        [Parameter(Mandatory=$false)]
        [SNMPv3PrivType]$PrivType = 'None',

        [Parameter(Mandatory=$false)]
        [String]$PrivSecret,

        [Parameter(Mandatory=$false)]
        [String]$Context,

        [Parameter(Mandatory=$false)]
        [int]$Port = 161,

        [Parameter(Mandatory=$false)]
        [int]$Timeout = 3000
    )

    $SecurityLevel = Get-SNMPv3SecurityLevel $AuthType $AuthSecret $PrivType $PrivSecret

    if ($SecurityLevel.IsValid)
    {
        $Authentication = Get-SNMPv3AuthenticationProvider $AuthType $AuthSecret
        $Privacy = Get-SNMPv3PrivacyProvider $PrivType $PrivSecret $Authentication
    }
    else
    {
        $InvalidSecurityLevel = [System.FormatException]::new('Invalid security level provided')
        Throw $InvalidSecurityLevel
    }

    $Context = if ([String]::IsNullOrWhiteSpace($Context)) {[String]::Empty} else {$Context}

    $IPAddress = [ipaddress]::None
    if ([ipaddress]::TryParse($Target, [ref]$IPAddress) -eq $false) {
        $IPAddress  = [System.Net.Dns]::GetHostEntry($Target).AddressList[0]
    }

    $IPEndPoint = [System.Net.IPEndPoint]::new($IPAddress, $Port)

    $Discovery = [Lextm.SharpSnmpLib.Messaging.Messenger]::GetNextDiscovery([Lextm.SharpSnmpLib.SnmpType]::GetBulkRequestPdu)
    $Report = $Discovery.GetResponse($Timeout, $IPEndPoint)

    $Result = [System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]]::new()

    [Lextm.SharpSnmpLib.Messaging.Messenger]::BulkWalk(
        [Lextm.SharpSnmpLib.VersionCode]::V3,
        $IPEndPoint,
        [Lextm.SharpSnmpLib.OctetString]::new($UserName),
        [Lextm.SharpSnmpLib.OctetString]::new($Context),
        [Lextm.SharpSnmpLib.ObjectIdentifier]::new($OID),
        $Result,
        $Timeout,
        10,
        [Lextm.SharpSnmpLib.Messaging.WalkMode]::WithinSubtree,
        $Privacy,
        $Report
    ) | Out-Null

    $Result | foreach {
        [PSCustomObject] @{
            PSTypeName = 'SNMPv3Output'
            Node       = $IPAddress
            OID        = $_.Id.ToString()
            Type       = $_.Data.TypeCode
            Value      = $_.Data
        }
    }
}
