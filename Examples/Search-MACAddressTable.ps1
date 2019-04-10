<##
 #
 # Use Invoke-SNMPv3Get and Invoke-SNMPv3Walk to search for a MAC address
 # in the MAC address table of Cisco Catalyst switches.
 #
 # If a MAC address has been learned on a trunk port you can use -Recurse to follow the 
 # address across neighbor switches until the correct port of the MAC address has been found.
 #
 # More info:
 # Using SNMP to Find a Port Number from a MAC Address on a Catalyst Switch
 # https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/44800-mactoport44800.html
 #
##>

function Search-MACAddressTable {
    [CmdletBinding()]
    param(
        [string]$Switch,
        [string]$MACAddress,
        [string]$UserName,
        [string]$AuthType,
        [string]$AuthSecret,
        [string]$PrivType,
        [string]$PrivSecret,
        [string]$Context,
        [switch]$Recurse,
        [int]$Timeout = 3000
    )
    
    $Verbose = [bool]$PSBoundParameters['Verbose']

    $sysName                    = '1.3.6.1.2.1.1.5'
    $vtpVlanState               = '1.3.6.1.4.1.9.9.46.1.3.1.1.2'
    $dot1dTpFdbAddress          = '1.3.6.1.2.1.17.4.3.1.1'
    $dot1dTpFdbPort             = '1.3.6.1.2.1.17.4.3.1.2'
    $dot1dBasePortIfIndex       = '1.3.6.1.2.1.17.1.4.1.2'
    $ifName                     = '1.3.6.1.2.1.31.1.1.1.1'
    $ifAlias                    = '1.3.6.1.2.1.31.1.1.1.18'
    $vlanTrunkPortDynamicStatus = '1.3.6.1.4.1.9.9.46.1.6.1.1.14'
    $cdpCacheAddress            = '1.3.6.1.4.1.9.9.23.1.2.1.1.4'
    $cdpCacheDeviceId           = '1.3.6.1.4.1.9.9.23.1.2.1.1.6'
    $cdpCacheNativeVLAN         = '1.3.6.1.4.1.9.9.23.1.2.1.1.11'

    $PhysicalAddress = [PhysicalAddress]::Parse(($MACAddress -replace '[^A-F0-9]+').ToUpper())
    $MACBytes        = $PhysicalAddress.GetAddressBytes()
    $MACDotted       = $MACBytes -join '.'
    $MACFormatted    = [System.BitConverter]::ToString($MACBytes)
    $IPAddress       = $null

    if (-not [IPAddress]::TryParse($Switch, [ref]$IPAddress)) {
        try {
            $IPAddress = [System.Net.DNS]::GetHostAddresses($Switch) | select -ExpandProperty IPAddressToString
        } catch {
            Write-Error -Message 'Unable to resolve host name' -ErrorAction Stop
        }
    }

    $PortMode = @{
        1 = 'Trunk'
        2 = 'Access'
    }

    $Request = @{
        UserName   = $UserName
        Target     = $IPAddress
        AuthType   = $AuthType
        AuthSecret = $AuthSecret
        PrivType   = $PrivType
        PrivSecret = $PrivSecret
        Timeout    = $Timeout
    }

    Write-Progress -Activity "Searching for $MACFormatted" -Status $IPAddress -CurrentOperation 'Collecting data'

    $VLANs = Invoke-SNMPv3Walk @Request -OID $vtpVlanState | foreach { $_.OID.Split('.') | select -Last 1 }

    foreach ($VLAN in $VLANs) {
        $Current = Invoke-SNMPv3Get @Request -OID "$dot1dTpFdbAddress.$MACDotted" -Context "vlan-$VLAN"
        if ($Current -and $Current.Type -ne 'NoSuchInstance') {
            $Found = $Current | select *, @{N='VLAN';E={[int]$VLAN}}
            break 
        }
    }

    if ($Found) {
        $Context = 'vlan-{0}' -f $Found.VLAN
        $BridgePort = (Invoke-SNMPv3Get @Request -OID "$dot1dTpFdbPort.$MACDotted" -Context $Context).Value
        $ifIndex    = (Invoke-SNMPv3Get @Request -OID "$dot1dBasePortIfIndex.$BridgePort" -Context $Context).Value
        $Port       = (Invoke-SNMPv3Get @Request -OID "$ifName.$ifIndex").Value
        $Switch     = (Invoke-SNMPv3Walk @Request -OID $sysName).Value
        $Desc       = (Invoke-SNMPv3Get @Request -OID "$ifAlias.$ifIndex").Value
        $Mode       = Invoke-SNMPv3Get @Request -OID "$vlanTrunkPortDynamicStatus.$ifIndex" | foreach { $_.Value.ToInt32() }
        $CDPHost    = (Invoke-SNMPv3Walk @Request -OID "$cdpCacheDeviceId.$ifIndex").Value
        $CDPVLAN    = Invoke-SNMPv3Walk @Request -OID "$cdpCacheNativeVLAN.$ifIndex" | foreach { $_.Value.ToInt32() }
        $CDPIPAddr  = Invoke-SNMPv3Walk @Request -OID "$cdpCacheAddress.$ifIndex" | foreach { [IPAddress]::new($_.Value.GetRaw()) }

        if ($Recurse -and $PortMode[$Mode] -eq 'Trunk' -and $Found.VLAN -ne $CDPVLAN) {
            Write-Verbose -Message "Moving on to $CDPHost"
            $Search = @{
                UserName   = $UserName
                Switch     = $CDPHost
                MACAddress = $MACAddress
                AuthType   = $AuthType
                AuthSecret = $AuthSecret
                PrivType   = $PrivType
                PrivSecret = $PrivSecret
                Timeout    = $Timeout
            }
            Search-MACAddressTable @Search -Recurse -Verbose:$Verbose
        } else {
            [PSCustomObject] @{
                MACAddress    = $MACFormatted
                Switch        = $Switch
                SwitchIP      = $IPAddress
                Port          = $Port
                VLAN          = $Found.VLAN
                Mode          = $PortMode[$Mode]
                Description   = $Desc
                CDPHostName   = $CDPHost
                CDPHostIP     = $CDPIPAddr
                CDPNativeVLAN = $CDPVLAN
            }
        }
    } else {
        Write-Warning "Could not find $MACFormatted on $Switch"
    }
}

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# In this example the MAC address was found on
# an access port without using -Recurse.

$Search = @{
    Switch     = 'switch1.mycompany.example'
    MACAddress = '00-00-5E-00-53-00'
    UserName   = 'MyUser'
    AuthType   = 'SHA1'
    AuthSecret = 'MyAuthSecret'
    PrivType   = 'AES256'
    PrivSecret = 'MyPrivSecret'
    Timeout    = 5000
}

Search-MACAddressTable @Search

<# Output:

MACAddress    : 00-00-5E-00-53-00
Switch        : switch1.mycompany.example
SwitchIP      : 192.0.2.5
Port          : Gi1/0/1
VLAN          : 100
Mode          : Access
Description   : HR Printer
CDPHostName   : 
CDPHostIP     : 
CDPNativeVLAN : 

#>

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# In this example the MAC address was found on
# a trunk port without using -Recurse.

$Search = @{
    Switch     = 'switch1.mycompany.example'
    MACAddress = '00-00-5E-00-53-11'
    UserName   = 'MyUser'
    AuthType   = 'SHA1'
    AuthSecret = 'MyAuthSecret'
    PrivType   = 'AES256'
    PrivSecret = 'MyPrivSecret'
    Timeout    = 5000
}

Search-MACAddressTable @Search

<# Output:

MACAddress    : 00-00-5E-00-53-11
Switch        : switch1.mycompany.example
SwitchIP      : 192.0.2.5
Port          : Gi1/0/25
VLAN          : 110
Mode          : Trunk
Description   : switch2
CDPHostName   : switch2.mycompany.example
CDPHostIP     : 192.0.2.6
CDPNativeVLAN : 999

#>

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# In this example the MAC address was found on a trunk port
# and tracked down to an access port using -Recurse. 
# Use -Verbose to show the path across switches.

$Search = @{
    Switch     = 'switch1.mycompany.example'
    MACAddress = '00-00-5E-00-53-22'
    UserName   = 'MyUser'
    AuthType   = 'SHA1'
    AuthSecret = 'MyAuthSecret'
    PrivType   = 'AES256'
    PrivSecret = 'MyPrivSecret'
    Timeout    = 5000
}

Search-MACAddressTable @Search -Recurse -Verbose

<# Output:

VERBOSE: Moving on to switch2.mycompany.example
VERBOSE: Moving on to switch3.mycompany.example


MACAddress    : 00-00-5E-00-53-22
Switch        : switch3.mycompany.example
SwitchIP      : 192.0.2.7
Port          : Gi1/0/5
VLAN          : 120
Mode          : Access
Description   : HR Workstation
CDPHostName   : 
CDPHostIP     : 
CDPNativeVLAN : 

#>
