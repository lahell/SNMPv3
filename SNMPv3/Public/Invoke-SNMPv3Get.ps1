function Invoke-SNMPv3Get
{
<#

.SYNOPSIS

    Query information from network devices using SNMP GET requests.

.DESCRIPTION

    Function supports SNMPv3 with security levels noAuthNoPriv, authNoPriv and authPriv.
    Based on #SNMP Library (https://www.sharpsnmp.com/) 

.PARAMETER UserName

    Username to use when polling information.

.PARAMETER Target

    SNMP Agent you want to get information from. Accepts IP address or host name.

.PARAMETER OID

    Object Identifier to get the value from.

.PARAMETER AuthType

    Allowed authentication types are None, MD5 and SHA1. Defaults to None.

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

    None. You cannot pipe objects to SNMPv3Get.

.OUTPUTS

    SNMPv3Output

.EXAMPLE

    PS> Invoke-SNMPv3Get -UserName usr-none-none -Target demo.snmplabs.com -OID 1.3.6.1.2.1.1.1.0

    Node           OID                      Type Value                                                          
    ----           ---                      ---- -----                                                          
    104.236.166.95 1.3.6.1.2.1.1.1.0 OctetString Linux zeus 4.8.6.5-smp #2 SMP Sun Nov 13 14:58:11 CDT 2016 i686

#>

    [CmdletBinding()]
    [OutputType('SNMPv3Output')]
    param(
        [Parameter(Mandatory=$true)]
        [String]$UserName,

        [Parameter(Mandatory=$true)]
        [String]$Target,

        [Parameter(Mandatory=$true)]
        [String[]]$OID,

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

    $SecurityLevel = Get-SharpSnmpSecurityLevel $AuthType $AuthSecret $PrivType $PrivSecret

    if ($SecurityLevel.IsValid)
    {
        $Authentication = Get-SharpSnmpAuthenticationProvider $AuthType $AuthSecret
        $Privacy = Get-SharpSnmpPrivacyProvider $PrivType $PrivSecret $Authentication
    }
    else
    {
        $InvalidSecurityLevel = [System.FormatException]::new('Invalid security level provided')
        Throw $InvalidSecurityLevel
    }

    $Context = if ([String]::IsNullOrWhiteSpace($Context)) {[String]::Empty} else {$Context}

    $IPAddress  = [System.Net.Dns]::GetHostEntry($Target).AddressList[0]
    $IPEndPoint = [System.Net.IPEndPoint]::new($IPAddress, $Port)

    $Discovery = [Lextm.SharpSnmpLib.Messaging.Messenger]::GetNextDiscovery([Lextm.SharpSnmpLib.SnmpType]::GetRequestPdu)
    $Report = $Discovery.GetResponse($Timeout, $IPEndPoint)

    $VariableList = [System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]]::new()

    foreach ($ObjectIdentifier in $OID)
    {
        $VariableList.Add([Lextm.SharpSnmpLib.ObjectIdentifier]::new($ObjectIdentifier))
    }

    $Request = [Lextm.SharpSnmpLib.Messaging.GetRequestMessage]::new(
        [Lextm.SharpSnmpLib.VersionCode]::V3,
        [Lextm.SharpSnmpLib.Messaging.Messenger]::NextMessageId,
        [Lextm.SharpSnmpLib.Messaging.Messenger]::NextRequestId,
        [Lextm.SharpSnmpLib.OctetString]::new($UserName),
        [Lextm.SharpSnmpLib.OctetString]::new($Context),
        $VariableList,
        $Privacy,
        [Lextm.SharpSnmpLib.Messaging.Messenger]::MaxMessageSize,
        $Report
    )

    $Reply = [Lextm.SharpSnmpLib.Messaging.SnmpMessageExtension]::GetResponse($Request, $Timeout, $IPEndPoint)

    if ($Reply -is [Lextm.SharpSnmpLib.Messaging.ReportMessage])
    {
        if ($Reply.Scope.Pdu.Variables.Count -eq 0)
        {
            Write-Warning "wrong report message received"
            return
        }

        $Id = $Reply.Scope.Pdu.Variables[0].Id
        if ($Id -ne [Lextm.SharpSnmpLib.Messaging.Messenger]::NotInTimeWindow)
        {
            $ErrMsg = [Lextm.SharpSnmpLib.Messaging.Messenger]::GetErrorMessage($Id)
            Write-Warning $ErrMsg
            return
        }

        # according to RFC 3414, send a second request to sync time.
        $Request = [Lextm.SharpSnmpLib.Messaging.GetRequestMessage]::new(
            [Lextm.SharpSnmpLib.VersionCode]::V3,
            [Lextm.SharpSnmpLib.Messaging.Messenger]::NextMessageId,
            [Lextm.SharpSnmpLib.Messaging.Messenger]::NextRequestId,
            [Lextm.SharpSnmpLib.OctetString]::new($UserName),
            [Lextm.SharpSnmpLib.OctetString]::new($Context),
            $VariableList,
            $Privacy,
            [Lextm.SharpSnmpLib.Messaging.Messenger]::MaxMessageSize,
            $Report
        )

        $Reply = [Lextm.SharpSnmpLib.Messaging.SnmpMessageExtension]::GetResponse($Request, $Timeout, $IPEndPoint)
    }
    elseif ($Reply.ErrorStatus -ne [Lextm.SharpSnmpLib.ErrorCode]::NoError)
    {
        throw [Lextm.SharpSnmpLib.Messaging.ErrorException]::Create(
            "error in response",
            $IPEndPoint.Address,
            $Reply
        )
    }

    $Reply.Scope.Pdu.Variables | foreach {
        [PSCustomObject] @{
            PSTypeName = 'SNMPv3Output'
            Node       = $IPAddress
            OID        = $_.Id.ToString()
            Type       = $_.Data.TypeCode
            Value      = $_.Data
        }
    }
}
