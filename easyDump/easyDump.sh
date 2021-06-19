#!/bin/sh
src_ip=$1
dst_ip=$2
port_=$3
para_cnt=$#



# 첫번째 인자를 인터페이스를 넣기
# -f : find interface
# => -f 옵션을 쓸때랑 다른 옵션쓸때랑 인자 다르게 만들어야함

# in(inbound) : using input = 출발지 아이피 인터페이스
# out(outbound) : using output = 목적지 아이피 인터페이스

# check para count & para 
if [ $# -le 1 ]; then
  echo "";
  echo "  [!] Usage : $0 <source IP> <Dest IP> <Port> ";
  echo "  [!] Plz Input Two or more parameters :)";
  echo "";
  exit 0
fi
# check Net or Host 
# 내가 입력한게 Host 인지 Network 대역인지 확인이 가능한 로직 필요


# check Interface
# 라우팅을 통해서 netstat -rn 으로 어떤 인터페이스를 통과하는지 확인할 수 있는 로직
# 한쪽은 무조건 디폴트로 찾아야함


# check Zone (Internal, Exteranl, DMZ)
# 해당인터페이스가 어떤 존인지 fw show conf | grep Z

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

echo "   [?] Choose inbound or outbound < Enter \"in\" or \"out\" >";
read target

#if문으로 in을 선택 시, 출발지 라우팅 인터페이스를, out선택시, 목적지라우팅 인터페이스를 나머지는 확인하라고하기

echo "";
echo "   [+] interface = $target";

# Go Tcpdump !!
dump="tcpdump -nni eth1 host $src_ip";
$dump
