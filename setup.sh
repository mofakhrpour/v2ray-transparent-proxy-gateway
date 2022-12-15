#!/bin/bash

trap on_exit EXIT

# Color codes
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color


#-- Varibles

#local
before_ip=''
after_ip=''
end_successfully=''
tproxy_status=''

#inline
verbose=''
routing_type=''
server_ip=''
upstream_proxy_ip=''
ssh_port=''



#-- Functions

print_log() {
  echo -e "\n${YELLOW}#-- ! LOG [this iptables rules are going to execute]:${NC}\n${YELLOW}#! ${NC}Title: ${PURPLE}${3}${NC}\n${YELLOW}#! ${NC}What's this rules for?: ${PURPLE}${4}${NC}\n${YELLOW}#! ${NC}Function name (in bash script): ${PURPLE}${1}${NC}" 1>&2
  
  if [[ $verbose != '' ]]; then
    echo -e "${YELLOW}#! ${NC}Commands: ${PURPLE}${2}${NC} \n${YELLOW}#-- ! END OF LOG. ${NC}" 1>&2
  else
    echo -e "${YELLOW}#! ${NC}Commands: ${PURPLE}To show 'iptables commands' start script with -v${NC} \n${YELLOW}#-- ! END OF LOG. ${NC}" 1>&2
  fi
}

_get_public_ip() {
  curl -s --max-time 4 https://ident.me
}


_iptables_gateway_tproxy_rules(){

  # iptable rules to execute

  command="
# Create V2RAY_PROXY_SYSTEM chain in 'mangle' table
iptables -t mangle -N V2RAY_PROXY_GATEWAY >/dev/null 2>&1

# Don't proxy System IP and Upstream IP 
iptables -t mangle -A V2RAY_PROXY_GATEWAY -d \$server_ip -j RETURN &&
if [[ \$upstream_proxy_ip != '' ]]; then
  iptables -t mangle -A V2RAY_PROXY_GATEWAY -d \$upstream_proxy_ip -j RETURN; 
fi &&
iptables -t mangle -A V2RAY_PROXY_GATEWAY -d 127.0.0.0/8,224.0.0.0/4,240.0.0.0/4 -j RETURN &&

# Don't proxy local IPs
iptables -t mangle -A V2RAY_PROXY_GATEWAY -p tcp -d 10.0.0.0/8,192.168.0.0/16,169.254.0.0/16,172.16.0.0/12 -j RETURN &&
iptables -t mangle -A V2RAY_PROXY_GATEWAY -p udp -d 10.0.0.0/8,192.168.0.0/16,169.254.0.0/16,172.16.0.0/12 ! --dport 53 -j RETURN &&

# Add TPROXY rules (redirect to v2ray)
iptables -t mangle -A V2RAY_PROXY_GATEWAY -p tcp -j TPROXY --on-port 1410 --tproxy-mark 0x01/0x01 &&
iptables -t mangle -A V2RAY_PROXY_GATEWAY -p udp --match multiport ! --dport 22,\$ssh_port -j TPROXY --on-port 1410 --tproxy-mark 0x01/0x01 &&

# Add V2RAY_PROXY_GATEWAY to PREROUTING chain in 'mangle' table
iptables -t mangle -A PREROUTING -j V2RAY_PROXY_GATEWAY"
  
  # end of rules 

  print_log "_iptables_gateway_tproxy_rules" "$command" "Gateway Rules" "redirect all incomming traffics (from your router) (udp, tcp) to v2ray port and this system will act as a gateway"

  get_confirm

  if [[ $? == 0 ]]; then
    eval "$command" 2>&1 && return 0 || return 1
  fi

  return 44

}


_iptables_system_tproxy_rules(){

  # iptable rules to execute

  command="
# Create V2RAY_PROXY_SYSTEM chain in 'mangle' table
iptables -t mangle -N V2RAY_PROXY_SYSTEM

# Don't proxy System IP and Upstream IP 
iptables -t mangle -A V2RAY_PROXY_SYSTEM -d \$server_ip -j RETURN &&
if [[ \$upstream_proxy_ip != '' ]]; then 
  iptables -t mangle -A V2RAY_PROXY_SYSTEM -d \$upstream_proxy_ip -j RETURN; 
fi &&
iptables -t mangle -A V2RAY_PROXY_SYSTEM -d 127.0.0.0/8,224.0.0.0/4,240.0.0.0/4 -j RETURN &&

# Don't proxy local IPs
iptables -t mangle -A V2RAY_PROXY_SYSTEM -p tcp -d 10.0.0.0/8,192.168.0.0/16,169.254.0.0/16,172.16.0.0/12 -j RETURN &&
iptables -t mangle -A V2RAY_PROXY_SYSTEM -p udp -d 10.0.0.0/8,192.168.0.0/16,169.254.0.0/16,172.16.0.0/12 ! --dport 53 -j RETURN &&

# Add TPROXY rules (redirect to v2ray)
iptables -t mangle -A V2RAY_PROXY_SYSTEM -p tcp -j TPROXY --on-port 1410 --tproxy-mark 0x01/0x01 &&
iptables -t mangle -A V2RAY_PROXY_SYSTEM -p udp --match multiport ! --dport 22,\$ssh_port -j TPROXY --on-port 1410 --tproxy-mark 0x01/0x01 &&

# Add V2RAY_PROXY_SYSTEM to OUTPUT chain in 'mangle' table
iptables -t mangle -A OUTPUT -j V2RAY_PROXY_SYSTEM"

  # end of rules 

  print_log "_iptables_system_tproxy_rules" "$command" "System Rules" "redirect outgoing traffics (udp, tcp) to v2ray port"
  
  get_confirm
  
  if [[ $? == 0 ]]; then
    eval "$command" 2>&1 && return 0 || return 1
  fi

  return 44

}


apply_iptables_rules() {

  flush_iptables_rules

  if [[ $routing_type == '1' ]] || [[ $routing_type == '3' ]]; then # Act as a gateway
    error=$(_iptables_gateway_tproxy_rules)
    code=$?
    if [[ $code != 0 ]] && [[ $code != 44 ]]; then
      echo -e "\n${RED}#-- * ERROR on apply TPROXY gateway rules\ndetaile:${NC} $error\n"
      # exit 1
    elif [[ $code == 44 ]]; then
      echo -e "\n${RED}#-- * SKIP this rules ${NC}\n"
    elif [[ $verbose != '' ]]; then
      echo -e "\n${BLUE}#-- # Executed successfully${NC}\n"
    fi
  fi

  if [[ $routing_type == '2' ]] || [[ $routing_type == '3' ]]; then # Proxy this system
    error=$(_iptables_system_tproxy_rules)
    code=$?
    if [[ $code != 0 ]] && [[ $code != 44 ]]; then
      echo -e "\n${RED}#-- * ERROR on apply TPROXY system rules\ndetaile:${NC} $error\n"
      # exit 1
    elif [[ $code == 44 ]]; then
      echo -e "\n${RED}#-- * SKIP this rules ${NC}\n"
    elif [[ $verbose != '' ]]; then
      echo -e "\n${BLUE}#-- # Executed successfully${NC}\n"
    fi
  fi

}


flush_iptables_rules() {

  $(exit 0) # set $? to 0
  while [[ $? == 0 ]]; do iptables -t mangle -D PREROUTING -j V2RAY_PROXY_GATEWAY >/dev/null 2>&1; done
  iptables -t mangle -F V2RAY_PROXY_GATEWAY >/dev/null 2>&1
  iptables -t mangle -X V2RAY_PROXY_GATEWAY >/dev/null 2>&1
  
  $(exit 0) # set $? to 0
  while [[ $? == 0 ]]; do iptables -t mangle -D OUTPUT -j V2RAY_PROXY_SYSTEM >/dev/null 2>&1; done
  iptables -t mangle -F V2RAY_PROXY_SYSTEM >/dev/null 2>&1
  iptables -t mangle -X V2RAY_PROXY_SYSTEM >/dev/null 2>&1
  
}

before_start() {

  $(iptables -t mangle -vnL V2RAY_PROXY_GATEWAY >/dev/null 2>&1)
  gateway_tproxy_status=$?

  $(iptables -t mangle -vnL V2RAY_PROXY_SYSTEM >/dev/null 2>&1)
  system_tproxy_status=$?

  if [[ $gateway_tproxy_status == 0 ]] || [[ $system_tproxy_status == 0 ]]; then
    echo -e -n "\n${YELLOW}#-- *${NC} You already have some iptables rules: "
    [[ $gateway_tproxy_status == 0 ]] && echo -e -n "[Gateway TPROXY] "
    [[ $system_tproxy_status == 0 ]] && echo -e -n "[System TPROXY] "

    echo -e "\n${YELLOW}#-- *${NC} Your new rules will be replaced with old ones. "
    echo -e "${BLUE}#-- ?${NC} Do you want to continue?"

    echo -e "  ${BLUE}1)${NC} Continue"
    echo -e "  ${BLUE}2)${NC} Remove rules and exit"
    echo -e "  ${BLUE}3)${NC} Exit"

    echo -n -e "Enter: ${PURPLE}"

    while read read_value; do
      if [[ $read_value == '1' ]]; then
        break
      elif [[ $read_value == '2' ]]; then
        flush_iptables_rules
        exit 0
      elif [[ $read_value == '3' ]]; then
        exit 0
      fi
    done

    echo -e ${NC}
  fi

}

try_load_tproxy() {
  MODULES="xt_TPROXY nf_tproxy_ipv4 nft_tproxy xt_socket xt_comment"

	# load Kernel Modules
	check_module_is_loaded(){
		if lsmod | grep $MODULE &> /dev/null; then return 0; else return 1; fi;
	}

	for MODULE in $MODULES; do
		if ! check_module_is_loaded; then
			modprobe $MODULE &> /dev/null
		fi
	done

  # test tproxy with a simple rule
  $(iptables -t mangle -A PREROUTING -p udp -d 123.123.123.123 -j TPROXY --on-port 1234 > /dev/null 2>&1 && iptables -t mangle -D PREROUTING -p udp -d 123.123.123.123 -j TPROXY --on-port 1234 > /dev/null 2>&1) 
  tproxy_status=$?

}

get_confirm() {
  echo -e -n "\n${BLUE}#-- ?${NC} Type 'yes' to execute this iptables rules ${YELLOW}[default: no]: ${NC}${PURPLE}" 1>&2
  read answer
  [[ $answer == 'yes' ]] && return 0 || return 1
}

on_exit() {
  echo -e ${NC}

  if [[ $end_successfully == 'true' ]]; then
    echo -e "DONE."
  fi
}




before_start
try_load_tproxy

#-- Fillup varibles

while [[ "$1" != '' ]]; do

  case $1 in
    -v)
      verbose=1
      shift 1
      ;;

    --routing-type)
      routing_type=$2
      shift 2
      ;;

    --server-ip)
      server_ip=$2
      shift 2
      ;;

    --ssh-port)
      ssh_port=$2
      shift 2
      ;;

    --upstream-proxy-ip)
      upstream_proxy_ip=$2
      shift 2
      ;;

    *)
      shift 1
      ;;
  esac
done

if [[ $routing_type == '' ]]; then

  if [[ $tproxy_status != 0 ]]; then
    echo -e "\n${YELLOW}#-- *${NC} TPROXY can't be enable in your linux kernel"
  fi
  echo -e "\n${BLUE}#-- ?${NC} Choice your Transparent Proxy routing type:"
  echo -e "  ${BLUE}1)${NC} Gateway [route incoming traffic to v2ray] ${YELLOW}*h:${NC} Act as a gateway"
  echo -e "  ${BLUE}2)${NC} System [route this system traffic to v2ray] ${YELLOW}*h:${NC} Proxy this server"
  echo -e "  ${BLUE}3)${NC} Both [gateway + system]" 

  echo -n -e "Enter: ${YELLOW}[default: 3] ${PURPLE}"

  while read read_value; do
    if [[ $read_value == '1' ]] || [[ $read_value == '2' ]] || [[ $read_value == '3' ]]; then
      routing_type=$read_value
      break
    elif [[ $read_value == '' ]]; then
      routing_type='3'
      break
    fi
  done

  echo -e -n "${NC}"
fi

if [[ $server_ip == '' ]]; then
  public_ip='';
  curl=$(_get_public_ip)

  if [[ $? == 0 ]] && [[ $curl != '' ]]; then
    public_ip=$curl
    before_ip=$curl
  fi

  echo -e "\n${BLUE}#-- ?${NC} What's your server public IP:"

  if [[ $public_ip == '' ]]; then
    echo -n -e "Enter: ${PURPLE}"
  else
    echo -n -e "Enter: ${YELLOW}[default: $public_ip  *h: maybe wrong!] ${PURPLE}"
  fi

  while read read_value; do
    if [[ $read_value != '' ]]; then
      server_ip=$read_value
      break
    elif [[ $read_value == '' ]]; then
      server_ip=$public_ip
      break
    fi
  done 

  echo -e -n "${NC}"
fi

if [[ $upstream_proxy_ip == '' ]]; then
  echo -e "\n${BLUE}#-- ?${NC} What's your Upsteam Proxy IP: (ex. Vmess upstream proxy)"

  echo -n -e "Enter: ${PURPLE}"

  while read read_value; do
    if [[ $read_value != '' ]]; then
      upstream_proxy_ip=$read_value
      break
    elif [[ $read_value == '' ]]; then
      upstream_proxy_ip=''
      break
    fi
  done 

  echo -e -n "${NC}"
fi

if [[ $ssh_port == '' ]]; then
  echo -e "\n${BLUE}#-- ?${NC} What's your server SSH port:"

  echo -n -e "Enter: ${YELLOW}[default: 22] ${PURPLE}"

  while read read_value; do
    if [[ $read_value != '' ]]; then
      ssh_port=$read_value
      break
    elif [[ $read_value == '' ]]; then
      ssh_port='22'
      break
    fi
  done 

  echo -e -n "${NC}"
fi


echo -e "\n"
echo -e "${BLUE}All varibles assigned.${NC}"
echo -e "${BLUE}Ready to start.${NC}"
echo -e "${BLUE}Starting ...${NC}"

apply_iptables_rules