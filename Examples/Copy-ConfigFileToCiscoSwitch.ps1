﻿# Prepare a hashtable with parameters
$Request = @{
    UserName   = 'MyUser'
    Target     = 'MySwitch'
    AuthType   = 'SHA1'
    AuthSecret = 'MyAuthSecret'
    PrivType   = 'AES256'
    PrivSecret = 'MyPrivSecret'
}

# Create config file on TFTP server
# The command snmp-server contact admin@mycompany.example will set 1.3.6.1.2.1.1.4.0 to admin@mycompany.example
New-Item -Path \\192.0.2.10\tftproot\sysContact.conf -Value 'snmp-server contact admin@mycompany.example'

# TFTP to Running-Config
$Random = Get-Random -Minimum 1 -Maximum ([int]::MaxValue)
Invoke-SNMPv3Set @Request -OID "1.3.6.1.4.1.9.9.96.1.1.1.1.2.$Random" -Type Integer -Value 1 # tftp
Invoke-SNMPv3Set @Request -OID "1.3.6.1.4.1.9.9.96.1.1.1.1.3.$Random" -Type Integer -Value 1 # networkFile
Invoke-SNMPv3Set @Request -OID "1.3.6.1.4.1.9.9.96.1.1.1.1.4.$Random" -Type Integer -Value 4 # runningConfig
Invoke-SNMPv3Set @Request -OID "1.3.6.1.4.1.9.9.96.1.1.1.1.5.$Random" -Type IPAddress -Value 192.0.2.10 # TFTP Server IP Address
Invoke-SNMPv3Set @Request -OID "1.3.6.1.4.1.9.9.96.1.1.1.1.6.$Random" -Type String -Value 'sysContact.conf' # Source File
Invoke-SNMPv3Set @Request -OID "1.3.6.1.4.1.9.9.96.1.1.1.1.14.$Random" -Type Integer -Value 1 # active

# Check Status
do {
    $Value = Invoke-SNMPv3Get @Request -OID "1.3.6.1.4.1.9.9.96.1.1.1.1.10.$Random" | select -Expand Value
    Start-Sleep -Seconds 1
} until ($Value.ToInt32() -gt 2)

# Destroy Row
Invoke-SNMPv3Set @Request -OID "1.3.6.1.4.1.9.9.96.1.1.1.1.14.$Random" -Type Integer -Value 6

# Display Result
switch ($Value.ToInt32()) {
    3 { Write-Host "Success!" -ForegroundColor Green }
    4 { Write-Host "Failure!" -ForegroundColor Red }
}

# Get the new value from sysContact
Invoke-SNMPv3Get @Request -OID 1.3.6.1.2.1.1.4.0
