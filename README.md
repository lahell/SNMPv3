![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/SNMPv3?color=808000&logo=powershell&logoColor=lightgrey&style=flat-square)
![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/SNMPv3?color=808000&style=flat-square)
![GitHub](https://img.shields.io/github/license/lahell/SNMPv3?color=808000&style=flat-square)

SNMPv3
======

PowerShell Module for SNMPv3

## Requirements
### Desktop
Windows PowerShell 5.1 and .NET Framework 4.7.1 or later

### Core
PowerShell 7.2 or later

## Installation

```PowerShell
Install-Module -Name SNMPv3
```

### Example of Invoke-SNMPv3Get with security model noAuthNoPriv

```PowerShell
$GetRequest = @{
    UserName = 'usr-none-none'
    Target   = 'demo.pysnmp.com'
    OID      = '1.3.6.1.2.1.1.1.0'
}

Invoke-SNMPv3Get @GetRequest | Format-Table -AutoSize
```

#### Output
```
Node           OID                      Type Value                       
----           ---                      ---- -----                       
20.163.207.223 1.3.6.1.2.1.1.1.0 OctetString #SNMP Agent on .NET Standard
```
### Example of Invoke-SNMPv3Walk with Context and security model authPriv

```PowerShell
$WalkRequest = @{
    UserName   = 'usr-sha-aes256'
    Target     = 'demo.pysnmp.com'
    OID        = '1.3.6.1.2.1.1'
    AuthType   = 'SHA1'
    AuthSecret = 'authkey1'
    PrivType   = 'AES256'
    PrivSecret = 'privkey1'
    Context    = 'da761cfc8c94d3aceef4f60f049105ba'
}

Invoke-SNMPv3Walk @WalkRequest | Format-Table -AutoSize
```

#### Output
```
Node           OID                               Type Value                       
----           ---                               ---- -----                       
20.163.207.223 1.3.6.1.2.1.1.1.0          OctetString #SNMP Agent on .NET Standard
20.163.207.223 1.3.6.1.2.1.1.2.0     ObjectIdentifier 1.3.6.1                     
20.163.207.223 1.3.6.1.2.1.1.3.0            TimeTicks 3.06:59:16.0700000          
20.163.207.223 1.3.6.1.2.1.1.4.0          OctetString UNKNOWN                     
20.163.207.223 1.3.6.1.2.1.1.5.0          OctetString UNKNOWN                     
20.163.207.223 1.3.6.1.2.1.1.6.0          OctetString                             
20.163.207.223 1.3.6.1.2.1.1.7.0            Integer32 72                          
20.163.207.223 1.3.6.1.2.1.1.8.0            TimeTicks 00:00:00                    
20.163.207.223 1.3.6.1.2.1.1.9.1.1.1        Integer32 1                           
20.163.207.223 1.3.6.1.2.1.1.9.1.1.2        Integer32 2                           
20.163.207.223 1.3.6.1.2.1.1.9.1.2.1 ObjectIdentifier 1.3                         
20.163.207.223 1.3.6.1.2.1.1.9.1.2.2 ObjectIdentifier 1.4                         
20.163.207.223 1.3.6.1.2.1.1.9.1.3.1      OctetString Test1                       
20.163.207.223 1.3.6.1.2.1.1.9.1.3.2      OctetString Test2                       
20.163.207.223 1.3.6.1.2.1.1.9.1.4.1        TimeTicks 00:00:00.0100000            
20.163.207.223 1.3.6.1.2.1.1.9.1.4.2        TimeTicks 00:00:00.0200000 
```
