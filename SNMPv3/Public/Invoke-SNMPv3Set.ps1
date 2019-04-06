function Invoke-SNMPv3Set
{
<#

.SYNOPSIS

    Update information on network devices using SNMP SET requests.

.DESCRIPTION

    Function supports SNMPv3 with security levels noAuthNoPriv, authNoPriv and authPriv.
    Based on #SNMP Library (https://www.sharpsnmp.com/) 

.PARAMETER UserName

    Username to use when updating information.

.PARAMETER Target

    SNMP Agent you want to connect to. Accepts IP address or host name.

.PARAMETER OID

    Object Identifier of the value to set.

.PARAMETER Type

    Data type of the value to set. The following data types are valid:

    Integer, Unsigned, String, HexString, DecimalString, NullObject, ObjectIdentifier, TimeTicks, IPAddress

.PARAMETER Value

    The value you want to set.

.PARAMETER AuthType

    Allowed authentication types are None, MD5, SHA1 and SHA256. Defaults to None.

.PARAMETER AuthSecret

    Authentication password used for security level authNoPriv and authPriv.

.PARAMETER PrivType

    Allowed encryption types are None, DES, TripleDES, AES128, AES192 and AES256. Defaults to None.

.PARAMETER PrivSecret

    Encryption password used for security level authPriv.

.PARAMETER Context

    Context to use.

.PARAMETER Port

    UDP port to use when connecting to the SNMP Agent. Defaults to 161.

.PARAMETER Timeout

    Timeout in milliseconds when connecting to SNMP Agent. Defaults to 3000.

.EXAMPLE

    PS> Invoke-SNMPv3Set -UserName usr-none-none -Target demo.snmplabs.com -OID 1.3.6.1.2.1.1.5.0 -Type String -Value SysName

    Node           OID                      Type Value  
    ----           ---                      ---- -----  
    104.236.166.95 1.3.6.1.2.1.1.5.0 OctetString SysName

#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]$UserName,

        [Parameter(Mandatory=$true)]
        [String]$Target,

        [Parameter(Mandatory=$true)]
        [String]$OID,

        [Parameter(Mandatory=$true)]  
        [ValidateSet('Integer', 'Unsigned', 'String', 'HexString', 'DecimalString', 'NullObject', 'ObjectIdentifier', 'TimeTicks', 'IPAddress')]
        [String]$Type,

        [Parameter(Mandatory=$true)]
        [Object]$Value,

        [Parameter(Mandatory=$false)]
        [ValidateSet('None', 'MD5', 'SHA1', 'SHA256')]
        [String]$AuthType = 'None',

        [Parameter(Mandatory=$false)]
        [String]$AuthSecret,

        [Parameter(Mandatory=$false)]
        [ValidateSet('None', 'DES', 'TripleDES', 'AES128', 'AES192', 'AES256')]
        [String]$PrivType = 'None',

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

    switch ($Type)
    {
        'Integer' { 
            $Data = [Lextm.SharpSnmpLib.Integer32]::new([int32]::Parse($Value))
        }
        'Unsigned' {
            $Data = [Lextm.SharpSnmpLib.Gauge32]::new([uint32]::Parse($Value))
        }
        'String' {
            $Data = [Lextm.SharpSnmpLib.OctetString]::new($Value)
        }
        'HexString' {
            $Data = [Lextm.SharpSnmpLib.OctetString]::new([Lextm.SharpSnmpLib.ByteTool]::Convert($Value))
        }
        'DecimalString' {
            $Data = [Lextm.SharpSnmpLib.OctetString]::new([Lextm.SharpSnmpLib.ByteTool]::ConvertDecimal($Value))
        }
        'NullObject' {
            $Data = [Lextm.SharpSnmpLib.Null]::new()
        }
        'ObjectIdentifier' {
            $Data = [Lextm.SharpSnmpLib.ObjectIdentifier]::new($Value)
        }
        'TimeTicks' {
            $Data = [Lextm.SharpSnmpLib.TimeTicks]::new([uint32]::Parse($Value))
        }
        'IPAddress' {
            $Data = [Lextm.SharpSnmpLib.IP]([IPAddress]::Parse($Value).GetAddressBytes())
        }
        default {
            Write-Warning "Unknown type string: $Type"
            return
        }
    }

    $Variable = [Lextm.SharpSnmpLib.Variable]::new([Lextm.SharpSnmpLib.ObjectIdentifier]::new($OID), $Data)
    $VariableList = [System.Collections.Generic.List[Lextm.SharpSnmpLib.Variable]]::new()
    $VariableList.Add($Variable)

    $Context = if ([String]::IsNullOrWhiteSpace($Context)) {[String]::Empty} else {$Context}

    $IPAddress  = [System.Net.Dns]::GetHostEntry($Target).AddressList[0]
    $IPEndPoint = [System.Net.IPEndPoint]::new($IPAddress, $Port)

    $Discovery = [Lextm.SharpSnmpLib.Messaging.Messenger]::GetNextDiscovery([Lextm.SharpSnmpLib.SnmpType]::GetRequestPdu)
    $Report = $Discovery.GetResponse($Timeout, $IPEndPoint)

    $Request = [Lextm.SharpSnmpLib.Messaging.SetRequestMessage]::new(
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
        $Request = [Lextm.SharpSnmpLib.Messaging.SetRequestMessage]::new(
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
            Node  = $IPAddress
            OID   = $_.Id.ToString()
            Type  = $_.Data.TypeCode
            Value = $_.Data
        }
    }
}
