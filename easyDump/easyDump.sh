#!/bin/sh
src_ip=$1
dst_ip=$2
port_=$3
para_cnt=$#

# 최상단에서 미리 인터페이스 정보 및 라우팅 빼오기
# check Interface
# 라우팅을 통해서 netstat -rn 으로 어떤 인터페이스를 통과하는지 확인할 수 있는 로직
# 한쪽은 무조건 디폴트로 찾아야함

# IP 정규표현식
#^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)

#netstat grep 결과가 변수에 제대로 저장이 안됨.. 파일쓰기로 해야하나?? 이건너무 비효율..
echo "test";
#parse= "netstat"
#$parse
echo "hi"
#echo $parse | grep eth[0-9];
echo "go"
#$parse

read a #temp 삭제예정

# check Zone (Internal, Exteranl, DMZ)
# 해당인터페이스가 어떤 존인지 fw show conf | grep Z

#깨끗하게 지우고 시작
clear

echo ""
echo " easyDump [Copyright(c) 2021 By IMyoungho]  ";
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


# show ip & port
echo ""
echo "============================================";
echo "";
echo "  [+] Source Ip = $src_ip";
echo "  [+] Destin Ip = $dst_ip";

if [ $para_cnt -eq 2 ]; then 
  echo "  [+] Port = < Empty >";
elif [ $port_ -ge 1 ] && [ $port_ -le 65535 ]; then
  echo "  [+] Port = $port_";
else
  #clear
  echo "  [!] Check the port range < 1 - 65535 > :(";
  echo ""
  exit 0
fi
echo "  [+] Zone = < >"; #temp 추후에 아이피 옆에 같이 출력함
echo "  [+] Interface = "; #temp 추후에 아이피 옆에 같이 출력함

echo "";
echo "--------------------------------------------";
echo "";
# 인터페이스 입력받기
echo "  [?] Choose inbound or outbound"
read -p "  [?] Enter \"in\" or \"out\" ] => " target
echo "";
echo "--------------------------------------------";
echo ""


#if문으로 in을 선택 시, 출발지 라우팅 인터페이스를, out선택시, 목적지라우팅 인터페이스를 나머지는 확인하라고하기
if [ $target == "in" ]; then
  echo "  [IN] Dump Inbound Traffic ";
elif [ $target == "out" ]; then
  echo "  [OUT] Dump Outbound Traffic ";
else
  #clear
  echo "  [!] syntex error => Enter \"in\" or \"out\" ";
  echo ""
  exit 0
fi
echo "  [=>] Start Tcpdump !!"
echo ""
echo "============================================";
echo ""
# start tcp dump
dump="tcpdump -nni eth1 host $src_ip";
$dump
