#!/bin/bash
src_ip=$1
dst_ip=$2
port_=$3
para_cnt=$#

# check para count & para 
if [ $# -le 1 ]; then
  echo "";
  echo "  [!] Usage : $0 <source IP> <Dest IP> <Port> ";
  echo "  [!] Plz Input Two or more parameters :)";
  echo "";
  exit 0
fi
# check Net or Host 


# check Interface


# check Zone (Internal, Exteranl, DMZ)


# show ip & port
echo "";
echo "  [+] Source Ip = $src_ip";
echo "  [+] Destin Ip = $dst_ip";

if [ $para_cnt -eq 2 ]; then 
  echo "  [+] Port = < Empty >";
elif [ $port_ -ge 1 ] && [ $port_ -le 65535 ]; then
  echo "  [+] Port = $port_";
else
  echo "  [!] Check the port range < 1 - 65535 > :(";
  exit 0
fi
echo "";


# Go Tcpdump !!
dump="tcpdump -nni eth1 host $src_ip";
$dump
