# 2026-10-20 10:00:00 by RouterOS 7.14
# software id = FAKE-0001
# FAKE SAMPLE CONFIG FOR TESTING CONFIGSENTRY - NOT FROM A REAL DEVICE
#
/interface list
add name=LAN
add name=WAN
add name=MGMT
/ip firewall filter
add action=accept chain=input connection-state=established,related
add action=accept chain=input src-address=198.51.100.0/24
add action=drop chain=input in-interface-list=WAN comment="drop all from WAN"
/ip neighbor discovery-settings
set discover-interface-list=LAN
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set api disabled=yes
set ssh address=198.51.100.0/24
set winbox address=198.51.100.0/24
set api-ssl address=198.51.100.0/24 \
    disabled=no
/snmp community
set [ find default=yes ] addresses=198.51.100.50/32 name=R3adOnly
/snmp
set enabled=yes
/system identity
set name=LAB-MT-02
/system logging action
set remote remote=198.51.100.20
/system ntp client
set enabled=yes servers=198.51.100.123
/tool bandwidth-server
set enabled=no
/tool mac-server
set allowed-interface-list=none
/tool mac-server mac-winbox
set allowed-interface-list=MGMT
