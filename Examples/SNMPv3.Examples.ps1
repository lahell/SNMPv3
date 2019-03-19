<##
 #
 # The examples below use the free and publicly available SNMP simulation service at demo.snmplabs.com
 #
 # More information: 
 # http://snmplabs.com/snmpsim/public-snmp-agent-simulator.html
 #
 # License:
 # http://snmplabs.com/snmpsim/license.html
 #
##>

Import-Module $PSScriptRoot\..\SNMPv3 -Force

# Example of Invoke-SNMPv3Get with security level noAuthNoPriv
$GetRequest = @{
    UserName = 'usr-none-none'
    Target   = 'demo.snmplabs.com'
    OID      = '1.3.6.1.2.1.1.1.0'
}

Invoke-SNMPv3Get @GetRequest | Format-Table -AutoSize

# Example of Invoke-SNMPv3Walk with Context and security level authPriv
$WalkRequest = @{
    UserName   = 'usr-sha-aes256'
    Target     = 'demo.snmplabs.com'
    OID        = '1.3.6.1.2.1.1'
    AuthType   = 'SHA1'
    AuthSecret = 'authkey1'
    PrivType   = 'AES256'
    PrivSecret = 'privkey1'
    Context    = 'da761cfc8c94d3aceef4f60f049105ba'
}

Invoke-SNMPv3Walk @WalkRequest | Format-Table -AutoSize

Pause
