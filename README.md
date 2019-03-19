SNMPv3
======

PowerShell Module for SNMPv3

### Example of Invoke-SNMPv3Get with security model noAuthNoPriv

```PowerShell
$GetRequest = @{
    UserName = 'usr-none-none'
    Target   = 'demo.snmplabs.com'
    OID      = '1.3.6.1.2.1.1.1.0'
}

Invoke-SNMPv3Get @GetRequest | Format-Table -AutoSize
```

#### Output
```
Node           OID               Type        Value                                                          
----           ---               ----        -----                                                          
104.236.166.95 1.3.6.1.2.1.1.1.0 OctetString Linux zeus 4.8.6.5-smp #2 SMP Sun Nov 13 14:58:11 CDT 2016 i686
```
### Example of Invoke-SNMPv3Walk with Context and security model authPriv

```PowerShell
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
```

#### Output
```
Node           OID               Type        Value                                                                                                                         
----           ---               ----        -----                                                                                                                         
104.236.166.95 1.3.6.1.2.1.1.1.0 OctetString Hardware: x86 Family 6 Model 9 Stepping 5 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free)
104.236.166.95 1.3.6.1.2.1.1.2.0 ObjectId    1.3.6.1.4.1.311.1.1.3.1.1                                                                                                     
104.236.166.95 1.3.6.1.2.1.1.3.0 TimeTicks   0d 0h 33m 28s 460ms                                                                                                           
104.236.166.95 1.3.6.1.2.1.1.4.0 OctetString info@snmplabs.com                                                                                                             
104.236.166.95 1.3.6.1.2.1.1.5.0 OctetString CRAY                                                                                                                          
104.236.166.95 1.3.6.1.2.1.1.6.0 OctetString Moscow, Russia                                                                                                                
104.236.166.95 1.3.6.1.2.1.1.7.0 Integer32   76                                                                                                                            
```
