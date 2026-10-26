# 2026-10-20 10:00:00 by RouterOS 7.12.1
# software id = FAKE-0000
# FAKE SAMPLE CONFIG FOR TESTING CONFIGSENTRY - NOT FROM A REAL DEVICE
#
/interface bridge
add name=bridge1
/ip address
add address=192.0.2.1/24 interface=bridge1 network=192.0.2.0
/ip dns
set allow-remote-requests=yes servers=203.0.113.53
/ip firewall filter
add action=accept chain=forward connection-state=established,related
/ip service
set ssh port=22
/ip socks
set enabled=yes
/ip upnp
set enabled=yes
/snmp
set enabled=yes
/system identity
set name=LAB-MT-01
/tool romon
set enabled=yes
