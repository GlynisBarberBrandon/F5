#!/bin/bash
# Copyright 2020, 2021, 2022, Fatih CELIK as COPYRIGHT HOLDER
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may
# be used to endorse or promote products derived from this software without 
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.


# NS to F5 
# Store a virtual server and its corresponding contents from a netscaler conf files to individual f5 config files.
# Before going further, you must be aware of some crucial points.
# First of all, i designed this script to transform NS virtual server configuration to F5 config.
# While looking for a way to trasnform configurations one to other, i simply wanted to make this easier as much as possible.
# As you probably guess it, i have found a script which written in PowerShell to split ns.conf file to individual files that 
# seperated by virtual server configurations. The name of script is "Get-ADCVServerConfig.ps" and the author is "C. Stalhood"
# Thanks for him to all efforts because that script files made this conversion progress a lot easier.
# The purpose of this script is to scan netscaler definitions and provide basic fetaures on F5 side. Not for the every single feature
# only for well known features supported like Vs (name, destination, tcp/udp) definition, pool, persistence, monitor(s), cache, compression, certificate profiles.

if [ $# -lt 1 ]; then
    echo "Sorry, Please follow to usage form"
    echo "Usage: nstoF5.sh ns.configfile"
    exit 33
fi

fileName="$1"
file=$( grep -vE "^#" "$fileName" | sed -e '/^ *$/d' )
DEBUG=1

##### Global Variables #####
RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

declare -A VSBODY 			# This array holds the VServer definitions
declare -A vsConstruct 		# Will be used when we constructing VServer definiton
outputFile=$( echo "Vs_config_${fileName}" | sed -e 's,nsconfig,f5,g;' )
namingIteration=1
ECVTRANSFORM=1 # Use this switch (=1) for traslate all HTTP-ECV type monitors to HTTP/HTTPS type customized monitors which is default behavior.
version="0.38"

#### Templates #####
external_http_monitor_template_1='
#!/bin/sh
# remove IPv6/IPv4 compatibility prefix (LTM passes addresses in IPv6 format)
IP=`echo ${1} | sed 's/::ffff://'`
PORT=${2}

PIDFILE="/var/run/`basename ${0}`.${IP}_${PORT}.pid"
# kill of the last instance of this monitor if hung and log current pid
if [ -f $PIDFILE ]
then
   echo "EAV exceeded runtime needed to kill ${IP}:${PORT}" | logger -p local0.error
   kill -9 `cat $PIDFILE` > /dev/null 2>&1
fi
echo "$$" > $PIDFILE

# send request & check for expected response
#curl -fNs http://${IP}:${PORT}${URI} | grep -i "${RECV}" 2>&1 > /dev/null
curl -fNsk ${SCHEME}://${IP}:${PORT}${URI} -H "${HEADER}" | grep -i "${RECV}" 2>&1 > /dev/null

# mark node UP if expected response was received
if [ $? -eq 0 ]
then
    rm -f $PIDFILE
    echo "UP"
else
    rm -f $PIDFILE
fi

exit
'

ltm_monitor_external_config_template_1='
ltm monitor external /Common/_LTM_EXT_MON_NAME_ {
    defaults-from /Common/external
    destination *:*
    interval 5
    run /Common/extmon_http_1
    time-until-up 0
    timeout 16
    user-defined HEADER _HEADER_STR_
    user-defined RECV _RECV_STR_
    user-defined URI _URI_STR_
    user-defined SCHEME _SCHEME_STR_
}
'

external_http_monitor_template_2='
#!/bin/sh
# remove IPv6/IPv4 compatibility prefix (LTM passes addresses in IPv6 format)
IP=`echo ${1} | sed 's/::ffff://'`
PORT=${2}

PIDFILE="/var/run/`basename ${0}`.${IP}_${PORT}.pid"
# kill of the last instance of this monitor if hung and log current pid
if [ -f $PIDFILE ]
then
   echo "EAV exceeded runtime needed to kill ${IP}:${PORT}" | logger -p local0.error
   kill -9 `cat $PIDFILE` > /dev/null 2>&1
fi
echo "$$" > $PIDFILE

# send request & check for expected response
curl -fNsk ${SCHEME}://${IP}:${PORT}${URI} | grep -i "${RECV}" 2>&1 > /dev/null
#curl -fNs http://${IP}:${PORT}${URI} -H "Host: ${HOST}" | grep -i "${RECV}" 2>&1 > /dev/null

# mark node UP if expected response was received
if [ $? -eq 0 ]
then
    rm -f $PIDFILE
    echo "UP"
else
    rm -f $PIDFILE
fi

exit
'

ltm_monitor_external_config_template_2='
ltm monitor external /Common/_LTM_EXT_MON_NAME_ {
    defaults-from /Common/external
    destination *:*
    interval 5
    run /Common/extmon_http_2
    time-until-up 0
    timeout 16
    user-defined RECV _RECV_STR_
    user-defined URI _URI_STR_
    user-defined SCHEME _SCHEME_STR_
}
'

######################

createPersistence(){
	# Persistence Profile
	
	log_debug "18" "Persistence Type is ${lbVsrvParams[persistenceType]}"
	case ${lbVsrvParams[persistenceType]} in 

		COOKIEINSERT)
		
			local cookie=""
			local cookieName=""
			
			if [[ $namingIteration ]]; then
				cookieName="${lbVsrvName}_cookie_persist"
			else
				cookieName="cookie_persist"
			fi
			cookie="ltm persistence cookie /Common/${cookieName} {"
			cookie=$(echo "$cookie"; echo "    defaults-from /Common/cookie")
			if [[ ${lbVsrvParams[timeout]} == "" ]] || [[ -z ${lbVsrvParams[timeout]} ]]; then # Persistence default value should be used.
				cookie=$(echo "$cookie"; echo "    expiration 2:0")
			elif [[ ${lbVsrvParams[timeout]} == 0 ]] ; then # Persist with Session Cookie
				cookie=$(echo "$cookie"; echo "    expiration 0")
			elif (( ${lbVsrvParams[timeout]} > 0 )) && (( ${lbVsrvParams[timeout]} < 60 )); then
				cookie=$(echo "$cookie"; echo "    expiration $(( ${lbVsrvParams[timeout]} * 60 )):0") # in Minutes:Seconds
			elif (( ${lbVsrvParams[timeout]} >= 60 )); then
				h=$(( ${lbVsrvParams[timeout]} / 60 )); m=$(( ${lbVsrvParams[timeout]} % 60 )); cookie=$(echo "$cookie"; echo "    expiration ${h}:${m}:0") # in Hours:Minutes:Seconds
			fi
			cookie=$(echo "$cookie"; echo "}")
			
			VSBODY[persist]="${cookieName}"
			vsConstruct[persistence]="${cookie}"

		;;

		SOURCEIP)
			
			local sourceIP=""
			local sourceIPName="${lbVsrvName}_src-addr_persist"
			
			sourceIP=$(echo "ltm persistence source-addr /Common/${sourceIPName} {" )
			if (( ${lbVsrvParams[timeout]} )); then
				sourceIP=$(echo "$sourceIP"; echo "    timeout $(( ${lbVsrvParams[timeout]} * 60 ))" )
			else
				sourceIP=$( echo "$sourceIP"; echo "    timeout 120" )
			fi
			sourceIP=$( echo "$sourceIP"; echo "}" )
			
			VSBODY[persist]="${sourceIPName}"
			vsConstruct[persistence]="${sourceIP}"

		;;
			
		URLPASSIVE)
			echo "URLPASSIVE persistence"
			# According to below calculations, there is no lb vserver definition which uses "URLPASSIVE" type persistence.
			# grep -rE "^add lb vserver(.*)URLPASSIVE" . | awk -F ":" '{ print $2 }'
			notes+=("URLPASSIVE Persistence is in use here. But the related codes not ready yet...")
		;;
		CALLID)
			echo "CALLID persistence"
			# According to below calculation method, there are two lb vservers which uses CALLID type persistence.
			# grep -rE "^add lb vserver(.*)CALLID" . | awk -F ":" '{ print $2 }'
			notes+=("CALLID Persistence is in use here. But the related codes not ready yet...")
		;;
		RULE)
			echo "RULE persistence"
			# According to below calculation method, there are only two definition.
			# grep -rE "^add lb vserver(.*)persis(.*)CALLID" . | awk -F ":" '{ print $2 }'
			notes+=("RULE Persistence is in use here. But the related codes not ready yet...")
		;;
		SSLSESSION)
			echo "SSLSESSION persistence"
			# According to below calcularion method, there plenty of (140) lb vserver definiton.
			# grep -rE "^add lb vserver(.*)persis(.*)SSLSESSION" . | awk -F ":" '{ print $2 }' 
			notes+=("SSLSESSION Persistence is in use here. But the related codes not ready yet...")
		;;
		*)
			echo "Different type of persistence"
		;;
		
	esac

}

createServerSSLProfile(){
	# Create Server SSL 
	local serverSSLName="$1" sslCrt sslKey sslChain sslConfLines serverSSLOptions serverSSLProfile serverSSLProfileName so
	sslConfLines=$( echo "$file" | grep -E "^(add|link) ssl certKey " )
	read -r sslCert sslKey <<< $( echo "$sslConfLines" | grep -E "add ssl certKey ${serverSSLName} " | awk '$5 == "-cert" && $7 == "-key" { print $6" "$8 }' )
	sslChain=$( echo "$sslConfLines" | grep -E "link ssl certKey ${serverSSLName} " | awk '{ print $5 }' )
	serverSSLOptions=$( { so=$( echo "$file" | grep -E "^set ssl serviceGroup ${sg} " | awk -F " ${sg} " '{ print $2 }' | sed -e 's,-,,g;s, DISABLED,DISABLED,g' | tr ' ' '\n' ); } && { echo "$so" | grep -E "ssl3DISABLED|tls1DISABLED|tls1DISABLED|tls12DISABLED" | sed -e 's,ssl3DISABLED,no-sslv3,g;s,tls1DISABLED,no-tlsv1,g;s,tls1DISABLED,no-tlsv1.1,g;s,tls12DISABLED,no-tlsv1.2,g'; } )
	serverSSLOptions=$( echo "$serverSSLOptions" | tr '\n' ' ' | sed -e 's, $,,g' )
	
	if [[ -n $serverSSLName ]] && [[ -n $sslCert ]] && [[ -n $sslKey ]]; then
	
		serverSSLProfileName="${serverSSLName}_serverssl"
		serverSSLProfile="ltm profile server-ssl /Common/${serverSSLProfileName} {"
		serverSSLProfile=$( echo "${serverSSLProfile}"; echo "    cert /Common/${sslCert}" )
		[[ $sslChain ]] && serverSSLProfile=$( echo "${serverSSLProfile}"; echo "    chain /Common/${sslChain}" )
		serverSSLProfile=$( echo "${serverSSLProfile}"; echo "    defaults-from /Common/serverssl" )
		serverSSLProfile=$( echo "${serverSSLProfile}"; echo "    key /Common/${sslKey}" )
		[[ $serverSSLOptions ]] && serverSSLProfile=$( echo "${serverSSLProfile}"; echo "    options { dont-insert-empty-fragments ${serverSSLOptions} }" )
		serverSSLProfile=$( echo "${serverSSLProfile}"; echo "}" )

		VSBODY[profiles]+="${serverSSLProfileName},"
		vsConstruct[serverssl]+="${serverSSLProfile},"
	else
		log_err "Either ServerSSL Profile Name or one of the SSL Cert, Key is missing"
	fi
}

createClientSSLProfile(){
	# Second Attempt to create a bunch of Client SSL profiles reagrdless of their count.
	local clientSSLName="$1" sslCrt sslKey sslChain sslConfLines clientSSLOptions clientSSLProfile clientSSLProfileName so
	
	sslConfLines=$( echo "$file" | grep -E "^(add|link) ssl certKey " )
	read -r sslCert sslKey <<< $( echo "$sslConfLines" | grep -E "add ssl certKey ${clientSSLName} " | awk '$5 == "-cert" && $7 == "-key" { print $6" "$8 }' )
	sslChain=$( echo "$sslConfLines" | grep -E "link ssl certKey ${clientSSLName} " | awk '{ print $5 }' )
	clientSSLOptions=$( { so=$( echo "$file" | grep -E "^set ssl vserver ${lbVsrvName} " | awk -F " ${lbVsrvName} " '{ print $2 }' | sed -e 's,-,,g;s, DISABLED,DISABLED,g' | tr ' ' '\n' ); } && { echo "$so" | grep -E "ssl3DISABLED|tls1DISABLED|tls1DISABLED|tls12DISABLED" | sed -e 's,ssl3DISABLED,no-sslv3,g;s,tls1DISABLED,no-tlsv1,g;s,tls1DISABLED,no-tlsv1.1,g;s,tls12DISABLED,no-tlsv1.2,g'; } )
	clientSSLOptions=$( echo "$clientSSLOptions" | tr '\n' ' ' | sed -e 's, $,,g' )
	
	if [[ -n $clientSSLName ]] && [[ -n $sslCert ]] && [[ -n $sslKey ]]; then
		log_debug "40" "$clientSSLName = (CERT) $sslCert + (KEY) $sslKey + (CHAIN) $sslChain"
		
		clientSSLProfileName="${clientSSLName}_clientssl"
		clientSSLProfile="ltm profile client-ssl /Common/${clientSSLProfileName} {"
		clientSSLProfile=$( echo "${clientSSLProfile}"; echo "    cert-key-chain {" )
		clientSSLProfile=$( echo "${clientSSLProfile}"; echo "        ${clientSSLProfileName}_bundle_0 {" )
		clientSSLProfile=$( echo "${clientSSLProfile}"; echo "            cert /Common/${sslCert}" )
		[[ $sslChain ]] && { clientSSLProfile=$(echo "${clientSSLProfile}"; echo "            chain /Common/${sslChain}"); }
		clientSSLProfile=$( echo "${clientSSLProfile}"; echo "            key /Common/${sslKey}" )
		clientSSLProfile=$( echo "${clientSSLProfile}"; echo "        }" )
		clientSSLProfile=$( echo "${clientSSLProfile}"; echo "    }" )
		clientSSLProfile=$( echo "${clientSSLProfile}"; echo "    defaults-from /Common/clientssl" )
		clientSSLProfile=$( echo "${clientSSLProfile}"; echo "    inherit-ca-certkeychain true" )
		clientSSLProfile=$( echo "${clientSSLProfile}"; echo "    inherit-certkeychain false" )
		[[ ${clientSSLOptions} ]] && { clientSSLProfile=$(echo "${clientSSLProfile}"; echo "    options { dont-insert-empty-fragments $clientSSLOptions no-tlsv1.3 }"); notes+=("options { dont-insert-empty-fragments no-tlsv1.3 } #SSL Options kısmına eklendi."); } # One of the best places to add "dont-insert-empty-fragments" option
		clientSSLProfile=$( echo "${clientSSLProfile}"; echo "}" )
		
		VSBODY[profiles]+="${clientSSLProfileName},"
		vsConstruct[clientssl]+="${clientSSLProfile},"
		
	else
		log_err "Either ClientSSL Profile Name or one of the SSL Cert, Key is missing"
	fi
	
}

createFallbackPersistence(){
	# Fallback Persistence Profile
	
	log_debug "20" "FallBack Persistence Type is ${lbVsrvParams[persistenceBackup]}"
	case ${lbVsrvParams[persistenceBackup]} in 

		COOKIEINSERT)
		
			local cookie=""
			local cookieName=""
			
			if [[ $namingIteration ]]; then
				cookieName="${lbVsrvName}_cookie_persist"
			else
				cookieName="cookie_persist"
			fi
			cookie="ltm persistence cookie /Common/${cookieName} {"
			cookie=$(echo "$cookie"; echo "    defaults-from /Common/cookie")
			[[ ${lbVsrvParams[backupPersistenceTimeout]} == 0 ]] && cookie=$(echo "$cookie"; echo "    expiration 0") # Persist with Session Cookie
			if (( ${lbVsrvParams[backupPersistenceTimeout]} > 0 )) && (( ${lbVsrvParams[backupPersistenceTimeout]} <= 60 )); then
				cookie=$(echo "$cookie"; echo "    expiration ${lbVsrvParams[backupPersistenceTimeout]}:0") # in Minutes:Seconds
			elif (( ${lbVsrvParams[backupPersistenceTimeout]} >= 60 )); then
				h=$(( ${lbVsrvParams[backupPersistenceTimeout]} / 60 )); m=$(( ${lbVsrvParams[backupPersistenceTimeout]} % 60 )); cookie=$(echo "$cookie"; echo "    expiration ${h}${m}:0") # in Hours:Minutes:Seconds
			fi
			cookie=$( echo "$cookie"; echo "}" )
			
			VSBODY[fallback]="${cookieName}"
			vsConstruct[fallback]="${cookie}"

			;;

		SOURCEIP)
			
			local sourceIP=""
			local sourceIPName="${lbVsrvName}_src-addr_persist"
			
			sourceIP=$(echo "ltm persistence source-addr /Common/${sourceIPName} {" )
			if (( ${lbVsrvParams[backupPersistenceTimeout]} )); then
				sourceIP=$(echo "$sourceIP"; echo "    timeout $(( ${lbVsrvParams[backupPersistenceTimeout]} * 60 ))" )
			else
				sourceIP=$(echo "$sourceIP"; echo "    timeout 120" )
			fi
			sourceIP=$( echo "$sourceIP"; echo "}" )
			
			VSBODY[fallback]="${sourceIPName}"
			vsConstruct[fallback]="${sourceIP}"

			;;
			
		URLPASSIVE)
			log_dbg "URLPASSIVE persistence" 
		;;
		CALLID)
			log_dbg "CALLID persistence"
		;;
		RULE)
			log_dbg "RULE persistence"
		;;
		SSLSESSION)
			log_dbg "SSLSESSION persistence"
		;;
		*)
			log_dbg "Different type of persistence"
		;;
		
	esac
		
}

responseHeaderReplace(){
	# This function add a policy which replaces Server Herader from server response
	# It's a globally declared feature and all virtual servers affected.
local zws_ServerHeaderMofify='ltm policy /Common/modify_Server_header_policy {
    requires { http }
    rules {
        replace_server_header_val {
            actions {
                0 {
                    http-header
                    response
                    replace
                    name Server
                    value zws
                }
            }
            conditions {
                0 {
                    http-header
                    response
                    name Server
                    not
                    values { zws }
                }
            }
        }
    }
    strategy /Common/first-match
}'
	local str1='add rewrite action Replace_WEBSERVER replace "HTTP.RES.HEADER(\\\"Server\\\"'
	local str2='add rewrite policy Change_Server_Header "http.res.header(\\\"Server\\\").exists'
	local str3='bind rewrite global Change_Server_Header 100 END -type RES_DEFAULT'
	local k="" m
	for m in "$str1" "$str2" "$str3"
	do
		echo "$file" | grep "$m" > /dev/null 2>&1
		if [ $? -eq 0 ]; then k+=$( echo -n 1 ); else k+=$( echo -n 0 ); fi
	done
	(( $k == 111 )) && { VSBODY[policies]+="modify_Server_header_policy,"; vsConstruct[policy]+="${zws_ServerHeaderMofify},"; }

}
cachingProfile(){
	# This func is adds caching pprofile if necessary
	# The necessity comes from original NS.config and
	# we just translate it to F5. Below (local "zb_cache") definition 
	# is our equal profile in F5. 
local zb_cache='ltm profile web-acceleration /Common/default_cache_profile {
    app-service none
    cache-aging-rate 9
    cache-object-max-size 1500000
    cache-object-min-size 100
    cache-size 1024mb
    defaults-from /Common/webacceleration
}'
	#~ enable ns feature IC
	#~ set cache parameter -memLimit 1024 -via ZB
	#~ add cache contentGroup DEFAULT
	#~ bind cache global NOPOLICY -priority 185883 -gotoPriorityExpression USE_INVOCATION_RESULT -type REQ_DEFAULT -invoke policylabel _reqBuiltinDefaults
	#~ bind cache global NOPOLICY -priority 185883 -gotoPriorityExpression USE_INVOCATION_RESULT -type RES_DEFAULT -invoke policylabel _resBuiltinDefaults

	local str1=('enable ns feature IC')
	local str1+=('set cache parameter -memLimit [0-9]+ -via ')
	local str1+=('add cache contentGroup DEFAULT')
	local str1+=('bind cache global NOPOLICY -priority 185883 -gotoPriorityExpression USE_INVOCATION_RESULT -type REQ_DEFAULT -invoke policylabel _reqBuiltinDefaults')
	local str1+=('bind cache global NOPOLICY -priority 185883 -gotoPriorityExpression USE_INVOCATION_RESULT -type RES_DEFAULT -invoke policylabel _resBuiltinDefaults')

	for i in "${!str1[@]}"
	do
		echo "$file" | grep -E "${str1[$i]}" > /dev/null 2>&1
		if [ $? -eq 0 ]; then z+=$( echo -n 1 ); else z+=$( echo -n 0 ); fi
	done

	if (( $z == 11111 )); then

		cacheSize=$( echo "$file" | awk '$2 == "cache" && $4 == "-memLimit" { print $5 }' )
		[[ $cacheSize ]] && (( $cacheSize > 0 )) && zb_cache=$( echo "$zb_cache" | sed -e "s,cache-size\(.*\),cache-size ${cacheSize}mb,g" )
		VSBODY[profiles]+="default_cache_profile,"
		vsConstruct[webaccel]+="${zb_cache},"
		notes+=("default_cache_profile eklendi. Cache-Size olarak orijinal tanım referans alındı.")

	fi
}
createPoolv2(){
	#Pool Profile Create Function
	local poolDefinition="" # real pool config for bigip.conf
    local poolName="${sg}_pool"
    local monitors=""
    local member 
    
    log_debug "5" "Create Pool v2 : ${poolName}"
    
			# Adding pool name and member stanzas. According to ==> poolMembers[0]="${srvcIP}:${srvcPort}:${srvName}:${srvcState}"
                    poolDefinition="ltm pool /Common/${poolName} {"
					[[ ${lbVsrvParams[lbMethod]} == "" ]] && poolDefinition=$( echo "${poolDefinition}"; echo "    load-balancing-mode least-connections-member") # -lbMethod (ROUNDROBIN|LEASTRESPONSETIME)
					poolDefinition=$( echo "${poolDefinition}"; echo -e "    members {" )
						# Adding members 
						(( ! ${#poolMembers[@]} )) && { log_err "Ooops, there is no pool member ? Quit..."; exit 39; }
						for member in "${!poolMembers[@]}"
						do
							
							poolDefinition=$(echo "${poolDefinition}"; echo "        /Common/$(echo ${poolMembers[$member]} | awk -F ":" '{ if ( $2 == "*" ) print $3":0"; else print $3":"$2 }' ) {")
							poolDefinition=$(echo "${poolDefinition}"; echo "            address $( echo ${poolMembers[$member]} | awk -F ":" '{ print $1 }' )")
							[[ ${poolMembers[$member]} == *:D ]] && poolDefinition=$(echo "${poolDefinition}"; echo "            session user-disabled")
							poolDefinition=$(echo "${poolDefinition}"; echo "        }")
						
						done
						
						poolDefinition=$(echo "${poolDefinition}"; echo "    }")
						if [ ${#monitor_sg[@]} -gt 1 ]; then
							monitors=$( printf "/Common/%s "  "${monitor_sg[@]}" | sed -e 's,ping,gateway_icmp,g' )
							poolDefinition=$(echo "${poolDefinition}"; echo "    monitor min 1 of { ${monitors} }")
							notes+=("Pool Monitor tanımlarında <monitor min of 1> kullanıldı. Bu belki değistirmek isteyebilirsiniz.")
						else
							# Adding Monitor and final braces
							poolDefinition=$( echo "${poolDefinition}"; echo -e "    monitor /Common/${monitor_sg[0]}" | sed -e 's,ping,gateway_icmp,g' )
							notes+=("Pool monitor tanımına bir göz atmak isteyebilirsiniz.")
						fi
						
						poolDefinition=$( echo "${poolDefinition}"; echo "}" )
						
						
	VSBODY[pool]="${poolName}"
	vsConstruct[pool]="$poolDefinition"
	log_debug "5" "Pool ${poolName} has been created with ${#poolMembers[@]} pieces of members."
}

parseParams(){
# Parsing Parameters
	  while read -r line
	  do
			f=$( echo "$line" | cut -d " " -f1 )
			s=$( echo "$line" | cut -d " " -f2- )
			echo -n ":$f==$s"	  
	  done < <(cat - | sed -e 's/^-//g;s/ -/\n/g' ) | sed -e 's/^://g'
	
}

createMonitor(){
	# this function tries to create a monitor definiton from scratch
	# There is one argument needs to send it which is monitor name"
	# Here we create a monitor and when we finish, we have to make a 
	# reservation for it on the VSadditionals array
	local monitorName="$1"
	local monType=""
	local monLine=""
	local f=""
	local s=""
	
	log_debug "12" "We will provide a monitor for $monitorName"
	echo "$file" | grep -E "^add lb monitor ${monitorName} " > /dev/null 2>&1
	if [ $? -eq 0 ]; then 
	
			read -r monType monLine <<< $( echo "$file" | grep -E "^add lb monitor ${monitorName} " | awk -F "add lb monitor ${monitorName} " '{ print $2 }' )
			declare -A monitorParams
			declare -g monitorDef
			declare -a tmpArry
			log_debug "13" "monType: $monType  monLine: $monLine"
			while read -r lines # Magnificent Line parser/delimiter!!
			do
				f=$( echo "$lines" | cut -d " " -f 1 )
				s=$( echo "$lines" | cut -d " " -f 2- )
				log_debug "13" "MonitorParams: ${f} == ${s}"
				monitorParams["${f}"]="${s}"
			done <<< $( echo "$monLine" | tr '-' '\n' | sed -e '/^ *$/d' )
			log_debug "14" "Monitor Parameters 2: $(declare -p monitorParams)"
			# Replace " MIN(utes)" with " 60" in interval definition on monitor.
			[[ ${monitorParams[resptimeout]} =~ MIN ]] && { monitorParams[resptimeout]=181; monitorParams[interval]=60; notes+=("Monitor tanımında dakika olarak görünen değerler degistirildi"); }
			[[ ${monitorParams[interval]} =~ MIN ]] && { monitorParams[interval]=60; monitorParams[resptimeout]=181; notes+=("Monitor tanımında dakika olarak görünen değerler degistirildi"); }
			# In case of Interval value is not defined, we add it with default values.
			if [[ ${monitorParams[interval]} == "" ]];then
				monitorParams[resptimeout]=5; monitorParams[interval]=5; notes+=("Monitor tanımında interval ve resptimeout default surelerle degistirildi.")
			else
				monitorParams[resptimeout]=${monitorParams[interval]}; notes+=("Monitor tanımında resptimeout interval degerine esitlendi.")
			fi
			
			(( ${ECVTRANSFORM} == 1 )) && [[ $monType == HTTP-ECV ]] && monType=TRANSFORM
			case $monType in 
				TRANSFORM)
						# Replacing HTTP-ECV type monitors with HTTP/HTTPS one.
						# Expected parameters : add lb monitor Bankkart_HCE_Mon HTTP-ECV -send "GET /cms/warmup.html" -recv OK -LRTM DISABLED -interval 3 MIN -resptimeout 10
						log_debug "15" "Monitor Type is a Translated HTTP/HTTPS one from HTTP-ECV" 
						
						if [[ ${monitorParams[secure]} == YES ]]; then
							monitorDef="ltm monitor https /Common/${monitorName} {"
							monitorDef=$( echo "${monitorDef}"; echo "    defaults-from /Common/https" )
						else
							monitorDef="ltm monitor http /Common/${monitorName} {"
							monitorDef=$( echo "${monitorDef}"; echo "    defaults-from /Common/http" )
						fi
						
						[[ ${monitorParams[interval]} ]] && monitorDef=$(echo "${monitorDef}"; echo "    interval ${monitorParams[interval]}")
						[[ ${monitorParams[recv]} ]] && monitorDef=$(echo "${monitorDef}"; echo "    recv ${monitorParams[recv]}")
						[[ ${monitorParams[send]} ]] && monitorDef=$(echo "${monitorDef}"; echo -n "    send ${monitorParams[send]}")
						[[ ${monitorParams[resptimeout]} ]] && monitorDef=$(echo "${monitorDef}"; echo -n "    timeout "; echo $(( ${monitorParams[resptimeout]} *3 +1)) )
						monitorDef=$( echo "${monitorDef}"; echo "}" )
	
						vsConstruct[monitor]+="${monitorDef},"
						notes+=("Monitor tanımı HTTP-ECV tipinden HTTP tipine degistirildi.")
				;;
				HTTP-ECV)
						log_debug "15" "Monitor Type is HTTP-ECV"
						# For creating an HTTP-ECV equivalent monitor, we should use LTM External Monitors.
						# We will replace convenient places in templates and this gives us a valid external monitor.
						# beware of HTTP-ECV monitors with "-customHeaders" option enabled
						# A Example: "add lb monitor Bankkart_HCE_Mon HTTP-ECV -send "GET /cms/warmup.html" -recv OK -LRTM DISABLED -interval 3 MIN -resptimeout 10"
						if [[ ${monitorParams[customHeaders]} == "" ]]; then
						
							# use non-Host header version
							bigipconfMonitorConf=""
							# This is for actual configuration details of new external monitor to store in bigip.conf
							bigipconfMonitorConf="${ltm_monitor_external_config_template_2}"
							# This is for actual external monitor definition.
							monitorDef="${external_http_monitor_template_2}"
							
						else 
						
							bigipconfMonitorConf=""
							# This is for actual configuration details of new external monitor to store in bigip.conf
							bigipconfMonitorConf="${ltm_monitor_external_config_template_1}"
							# This is for actual external monitor definition.
							monitorDef="${external_http_monitor_template_1}"
							# add codes for "-customHeaders" option to send _HEADER_STR_ info
							if [ ${monitorParams[$customHeaders]} == Host:* ]; then
								# if -customHeaders contains "Host:" value, we could convert the whole string to F5
								hostHeader=$( echo ${monitorParams[$customHeaders]} | sed -e 's,http://,,g;s,https://,,g;s,/\(.*\),,g' )
								bigipconfMonitorConf=$( echo "$bigipconfMonitorConf" | sed -e "s,_HEADER_STR_,${hostHeader},g" )
							else
								# IF -customHeaders doesn't contain "Host:", so we can add it as its original form
								bigipconfMonitorConf=$( echo "$bigipconfMonitorConf" | sed -e "s,_HEADER_STR_,${monitorParams[$customHeaders]},g" )
							fi
							
						fi		
						# Here we replace original values of _RECV_STR_ <-> $recv, _URI_STR_ <-> $send and profile name
						# which is _LTM_EXT_MON_NAME_ <-> $monitorName
						bigipconfMonitorConf=$( echo "$bigipconfMonitorConf" | sed -e "s,_LTM_EXT_MON_NAME_,${monitorName},g" )
						bigipconfMonitorConf=$( echo "$bigipconfMonitorConf" | sed -e "s,_RECV_STR_,${monitorParams[recv]},g" )
						bigipconfMonitorConf=$( echo "$bigipconfMonitorConf" | sed -e "s,_URI_STR_,$(echo ${monitorParams[send]} | sed -e 's,GET \|POST \|HEAD \|OPTIONS ,,g'),g" )
						if [[ ${monitorParams[secure]} == YES ]]; then
							bigipconfMonitorConf=$( echo "$bigipconfMonitorConf" | sed -e "s,_SCHEME_STR_,https,g" )
						else
							bigipconfMonitorConf=$( echo "$bigipconfMonitorConf" | sed -e "s,_SCHEME_STR_,http,g" )
						fi
						
						log_debug "16" "External monitor definition completed."
						log_debug "16" "#### Monitor Definition for bigip.conf ####"
						log_debug "16" "$bigipconfMonitorConf"
						log_debug "16" "#### External Monitor Script for bigip.conf ####"
						log_debug "16" "$monitorDef"
						log_debug "16" "####"
	
						# Now, it's time to register our monitor definition and it's external monitor
						vsConstruct[monitor]+="${bigipconfMonitorConf},"
						vsConstruct[ext-mon]="$monitorDef"
						
				;;
				HTTPS)
						log_debug "15" "Monitor Type is HTTPS"
						# According to my Grep-Fu ( grep -rE "^add lb monitor " . | awk -F ":" '{ print $2 }' ) there is no HTTPS custom monitor.
						notes+=("HTTPS monitor tanımlası bulundu. Ancak bu tip bir monitör için gerekli kodlar yazılmadı.")
				;;
				HTTP)
						log_debug "15" "Monitor Type is HTTP"
						# Expected paramters for custom HTTP monitor:
						# add lb monitor "http allow more response codes" HTTP -respCode 200 301-302 -httpRequest "HEAD /" -LRTM ENABLED -interval 6 -resptimeout 5 -alertRetries 1 -downTime 5
						# Basic Calculations for Interval and responsetimeout
						
						if [[ ${monitorParams[secure]} == YES ]]; then # If "-secure YES" then we should change some parameters to fit https monitors
							monitorDef=$(echo "ltm monitor https /Common/${monitorName} {" )
							monitorDef=$( echo "$monitorDef"; echo "    defaults-from /Common/https" )
							notes+=("-secure YES: Monitör tanımı https tipinde olusturuldu.")
						else
							monitorDef=$(echo "ltm monitor http /Common/${monitorName} {" )
							monitorDef=$( echo "$monitorDef"; echo "    defaults-from /Common/http" )
						fi
						log_debug "1000" "destPort: ${monitorParams[destPort]}"
						[[ ${monitorParams[destPort]} ]] && monitorDef=$( echo "$monitorDef"; echo "    destination *:${monitorParams[destPort]}" )
						[[ ${monitorParams[interval]} ]] && monitorDef=$( echo "$monitorDef"; echo "    interval ${monitorParams[interval]}" ) 
						[[ ${monitorParams[respCode]} ]] && monitorDef=$( echo "$monitorDef"; echo "    recv ${monitorParams[respCode]}" ) 
						[[ ${monitorParams[httpRequest]} ]] && monitorDef=$( echo "$monitorDef"; echo "    send ${monitorParams[httpRequest]}" )
						[[ ${monitorParams[resptimeout]} ]] && monitorDef=$( echo "$monitorDef"; echo "    timeout $( echo $(( ${monitorParams[resptimeout]} *3 +1)) )" )
						monitorDef=$( echo "$monitorDef"; echo "}" )
						
						vsConstruct[monitor]+="${monitorDef},"
						notes+=("HTTP monitor tanımı içideki <recv> parametresi için herhangi bir kontrol yapısı kullanılmamıstır. Doğruluğunu kontrol ediniz.")
					
				;;
				RTSP)
						log_debug "15" "Monitor Type is RTSP"
						# Looks like there is no valid and attached monitor configuration for RTSP
						notes+=("RTSP monitor tanımlası bulundu. Ancak bu tip bir monitör için gerekli kodlar yazılmadı.")
				;;
				SIP-UDP)
						log_debug "15" "Monitor Type is SIP-UDP"
						notes+=("SIP-UDP monitor tanımlası bulundu. Ancak bu tip bir monitör için gerekli kodlar yazılmadı.")
				;;
				TCP-ECV)
						log_debug "15" "Monitor Type is TCP-ECV"
						monitorDef="ltm monitor tcp /Common/${monitorName} {"
						monitorDef=$(echo "${monitorDef}"; echo "    defaults-from /Common/tcp" )
						[[ ${monitorParams[destPort]} ]] && monitorDef=$(echo "${monitorDef}"; echo "    destination *:${monitorParams[destPort]}" )
						[[ ${monitorParams[interval]} ]] && monitorDef=$(echo "${monitorDef}"; echo "    interval ${monitorParams[interval]}" )
						[[ ${monitorParams[send]} ]] && monitorDef=$(echo "${monitorDef}"; echo "    send ${monitorParams[send]}" )
						[[ ${monitorParams[recv]} ]] && monitorDef=$(echo "${monitorDef}"; echo "    recv ${monitorParams[recv]}" )
						[[ ${monitorParams[resptimeout]} ]] && monitorDef=$(echo "${monitorDef}"; echo "    timeout $( echo $(( ${monitorParams[resptimeout]} *3 +1)) )" )
						monitorDef=$(echo "${monitorDef}"; echo "}" )
						
						vsConstruct[monitor]+="${monitorDef},"
						notes+=("Custom TCP-ECV icin monitor eklendi. Tanımın send recv destPort parametrelerine bakmanız gerekebilir.")
				;;
				TCP)
						log_debug "15" "Monitor Type is TCP"
						monitorDef="ltm monitor tcp /Common/${monitorName} {"
						monitorDef=$(echo "${monitorDef}"; echo "    defaults-from /Common/tcp" )
						[[ ${monitorParams[destPort]} ]] && monitorDef=$(echo "${monitorDef}"; echo "    destination *:${monitorParams[destPort]}" )
						[[ ${monitorParams[interval]} ]] && monitorDef=$(echo "${monitorDef}"; echo "    interval ${monitorParams[interval]}" )
						[[ ${monitorParams[resptimeout]} ]] && monitorDef=$(echo "${monitorDef}"; echo "    timeout $( echo $(( ${monitorParams[resptimeout]} *3 +1)) )" )
						monitorDef=$(echo "${monitorDef}"; echo "}" )
						
						vsConstruct[monitor]+="${monitorDef},"
						notes+=("Custom TCP monitor eklendi. Tanımın send recv destPort parametrelerine bakmanız gerekebilir.")
				;;
				*)
						log_dbg "Something went wrong in createMonitor() fuction"
				;;
			
			esac
		unset monitorParams
	
	else
	
		# Seems like there is no "add lb monitor" lines here. There must be something wrong
		# When a monitor could not detect as an predefined default monitor (like tcp|http ) in previous function
		# this could be the reason why this happening. So, we should check that predefined monitors.
		
		echo "Add some codes to use default tcp monitor in pool here"
	
	fi

}
log_info() {
    msg=$1
    #~ date=$(date +%F:%X)
    #~ echo -e "[${date}][${BLUE}INF${NC}] nstoF5: ${msg}"
    echo -e "[${BLUE}INF${NC}] nstoF5: ${msg}"
}

log_err() {
    msg=$1
    date=$(date +%F:%X)
    echo -e "[${date}][${RED}ERR${NC}] nstoF5: ${msg}" 1>&2
}

log_debug() {
    if (( ${DEBUG} == 1 )); then
		code=$1
        msg=$2
        #~ date=$(date +%F:%X)
        #~ echo -e "[${date}][${YELLOW}DBG${NC}] nstoF5: ${msg}" 1>&2
        echo -e "[${YELLOW}DBG-${code}${NC}] nstoF5: ${msg}" 1>&2
    fi
}
log_dbg() {
    if (( ${DEBUG} == 1 )); then
        msg=$1
        #~ date=$(date +%F:%X)
        #~ echo -e "[${date}][${YELLOW}DBG${NC}] nstoF5: ${msg}" 1>&2
        echo -e "[${YELLOW}DBG${NC}] nstoF5: ${msg}" 1>&2
    fi
}
checkXFFRequire(){
	# Sometimes XFF required globally despite definition CIP=DISABLE
	local i e
	local s1='bind rewrite global xff_header_insertion 100 END -type REQ_DEFAULT'
	local s2='add rewrite policy xff_header_insertion true xff_header_insertion'
	local s3='add rewrite action xff_header_insertion insert_http_header XFF CLIENT.IP.SRC'

	for i in "$s1" "$s2" "$s3" 
	do
		echo "$file" | grep "${i}" > /dev/null 2>&1
		if [ $? -eq 0 ]; then e+="1"; else e+="0"; fi
	
	done
	if [[ $e == 111 ]]; then
		echo "TRUE"
	else
		echo "FALSE"
	fi
}


#### main(){

vSrvCount=$( echo "$file" | grep -Ec "^add lb vserver " )
sgCount=$( echo "$file" | grep -cE "^add serviceGroup ")
if [ $vSrvCount -gt 1 ]; then
	 log_err "Looks like there is a fatal error."
	 log_err "There are $vSrvCount pieces of lb vserver definition"
	 log_err "There are $sgCount pieces of Service Group definitions"
	 exit 35
fi

declare -a servers
declare -A SERVERS
read -a servers <<< $( echo "$file" | grep -E "^add server " | awk '{ print $3"::"$4 }' | tr '\n' ' ')
log_debug "3" "server array $(declare -p servers)"
for i in "${!servers[@]}"
do
	log_debug "3" "$i -> ${servers[$i]}"
	f=$( echo "${servers[$i]}" | awk -F "::" '{ print $1 }' )
	s=$( echo "${servers[$i]}" | awk -F "::" '{ print $2 }' )
	# SERVERS[name]=IPADDR
	SERVERS["$f"]="$s"
done
log_debug "3" "SERVERS are : $(declare -p SERVERS)"


echo "$file" | grep -E "^bind service |^add service " > /dev/null 2>&1
if [ $? -eq 0 ]; then
	ISSERVICE=TRUE
else
	ISSERVICE=FALSE
fi
log_debug "1" "### ISSERVICE == ${ISSERVICE} ###"

if [[ $ISSERVICE == TRUE ]]; then
	# Example:
	# add server 172.22.21.15 172.22.21.15
	# add server 172.22.21.16 172.22.21.16
	# add server 172.22.21.17 172.22.21.17
	# add server 172.22.21.18 172.22.21.18
	#~ add lb monitor seal_test_19080 HTTP -respCode 200 -httpRequest "GET /actuator/health" -LRTM DISABLED -destPort 19080
	#~ add lb monitor seal_test_19081 HTTP -respCode 200 -httpRequest "GET /actuator/health" -LRTM DISABLED -destPort 19081
	#~ add lb monitor seal_test_19082 HTTP -respCode 200 -httpRequest "GET /actuator/health" -LRTM DISABLED -destPort 19082
	#~ add lb monitor seal_test_19083 HTTP -respCode 200 -httpRequest "GET /actuator/health" -LRTM DISABLED -destPort 19083
	#~ add lb monitor seal_test_19084 HTTP -respCode 200 -httpRequest "GET /actuator/health" -LRTM DISABLED -destPort 19084
	#~ add lb monitor seal_test_19085 HTTP -respCode 200 -httpRequest "GET /actuator/health" -LRTM DISABLED -destPort 19085
	#~ add lb monitor seal_test_19086 HTTP -respCode 200 -httpRequest "GET /actuator/health" -LRTM DISABLED -destPort 19086
	#~ add lb monitor seal_test_19087 HTTP -respCode 200 -httpRequest "GET /actuator/health" -LRTM DISABLED -destPort 19087
	#~ add lb monitor seal_test_19088 HTTP -respCode 200 -httpRequest "GET /actuator/health" -LRTM DISABLED -destPort 19088
	#~ add lb monitor seal_test_19089 HTTP -respCode 200 -httpRequest "GET /actuator/health" -LRTM DISABLED -destPort 19089
	# add service 172.22.21.15_9080 172.22.21.15 HTTP 9080 -gslb NONE -maxClient 0 -maxReq 0 -cip DISABLED -usip NO -useproxyport YES -sp ON -cltTimeout 180 -svrTimeout 360 -CKA YES -TCPB NO -CMP YES
	# bind service 172.22.21.15_9080 -monitorName seal_test_19080
	#~ add service 172.22.21.16_9083 172.22.21.16 HTTP 9083 -gslb NONE -maxClient 0 -maxReq 0 -cip DISABLED -usip NO -useproxyport YES -sp ON -cltTimeout 180 -svrTimeout 360 -CKA YES -TCPB NO -CMP YES
	#~ bind service 172.22.21.16_9083 -monitorName seal_test_19083
	#~ add service 172.22.21.17_9080 172.22.21.17 HTTP 9080 -gslb NONE -maxClient 0 -maxReq 0 -cip DISABLED -usip NO -useproxyport YES -sp ON -cltTimeout 180 -svrTimeout 360 -CKA YES -TCPB NO -CMP YES
	#~ bind service 172.22.21.17_9080 -monitorName seal_test_19080
	# add lb vserver Codevo_SEAL_443_VIP SSL 172.22.22.14 443 -persistenceType NONE -cltTimeout 180 -backupVServer Codeva_Seal_RST_VIP
	# bind lb vserver Codevo_SEAL_443_VIP 172.22.21.15_9080
	# bind lb vserver Codevo_SEAL_443_VIP 172.22.21.15_9081

	# lets find vservername and its type
		declare -A lbVsrvParams
		declare -a tmpArry
		read -r lbVserverName lbVserverType lbVserverIP lbVserverPort <<< $( echo "$file" | grep -E "^add lb vserver " | awk '{ print $4" "$5" "$6" "$7 }' )
		IFS=- read -a tmpArry <<< $( echo "$file" | grep -E "^add lb vserver " | awk -F "$lbVserverIP $lbVserverPort " '{ print $2 }' | sed -e 's,^-,,g' )
		log_debug "30" "lbServerName: ${lbVserverName}, lbSrvType: ${lbVserverType}, lbServerIP: ${lbVserverIP}, lbServerPort: ${lbVserverPort}"
		log_debug "30" "$(declare -p tmpArry)"
		for lbparam in "${!tmpArry[@]}" # transfer data from tmpArry to lbVsrvParams array
		do
			f=$( echo "${tmpArry[$lbparam]}" | cut -d " " -f1 )
			s=$( echo "${tmpArry[$lbparam]}" | cut -d " " -f2- | sed -e 's,[[:space:]]$,,g')
			
			lbVsrvParams["$f"]="$s"
		done
		unset tmpArry
		log_debug "30" "lbServerParam = $(declare -p lbVsrvParams)"
		
		echo "${lbVserverType}" | grep -iE "HTTP|FTP|TCP|SSL|SSL_BRIDGE|SSL_TCP|SIP_TCP|SIP_SSL|DNS_TCP|RTSP|PUSH|SSL_PUSH|RDP|MYSQL|MSSQL|DIAMETER|SSL_DIAMETER|SYSLOGTCP|SMPP|PROXY|USER_TCP|USER_SSL_TCP|IPFIX" > /dev/null 2>&1 
		if [ $? -eq 0 ]; then
			F5VirtSrvType=tcp
		else
			F5VirtSrvType=udp
		fi
		
		declare -a serviceArray
		while read -r line
		do
			serviceArray+=( "$line" )
		done < <( for serverName in "${!SERVERS[@]}"; do echo "$file" | grep -E "^add service (.*) $serverName "; done )
		log_debug "31" "$(declare -p serviceArray)"
		unset serverName
		
		declare -A SERVICES
		declare -A sg_params
		zz=0
		# Let's find Services and all services related definitons.
		for srvcLine in "${!serviceArray[@]}" # this array contains whole "add service" lines so before use it, we have to parse it.
		do	

			 read -r srvcName srvName srvcType srvcPort <<< $( echo "${serviceArray[$srvcLine]}" | awk '{ print $3" "$4" "$5" "$6 }' ) # Actually: "add service OBSD-http-1 OBSD-http-23.123 HTTP 80 -gslb NONE ..." -> "OBSD-http-1 OBSD-http-23.123 HTTP 80"
			 if (( $zz == 0 )); then
				type="${srvcType}"
				sg="${lbVserverName}"
				IFS=- read -a tempArry <<< $( echo "${serviceArray[$srvcLine]}" | cut -d " " -f5- )
				for _param in "${!tempArry[@]}"
				do
					f=$(echo "${tempArry[$_param]}" | cut -d " " -f1 )
					s=$(echo "${tempArry[$_param]}" | cut -d " " -f2- | sed -e 's,[[:space:]]$,,g' )
					sg_params["$f"]="$s"
				done
				log_debug "31" "SG_PARAMS: $(declare -p sg_params)"
			 fi
			 if [[ ${serviceArray[$srvcLine]} =~ state\ DISABLED ]]; then srvcState="D"; else srvcState="E"; fi
			 srvcIP="${SERVERS[$srvName]}"
			 monitorLine=$( echo "$file" | grep -E "^bind service ${srvcName} " | sed -e "s/bind service ${srvcName} //g")
			 if [[ ${monitorLine} =~ monitorName ]]; then monName=$( echo "$monitorLine" | awk -F "-monitorName " '{ print $2 }' | awk '{ print $1 }' ); else monName="${F5VirtSrvType}"; fi
			 (( $zz == 0 )) && monitorName="${monName}"
			 log_debug "32" "srvcName: $srvcName srvName: $srvName srvcType: $srvcType srvcIP: $srvcIP srvcPort: $srvcPort monName: $monName"
			 SERVICES["$srvcName"]="${srvcIP}:${srvcPort}:${srvName}:${srvcType}:${monName}:${srvcState}" # Example :: srvcName: OBSD-http-2 srvName: OBSD-http-23.124 srvcType: HTTP srvcIP: 10.34.23.124 srvcPort: 80 monName: tcp
			 echo "$file" | grep -E "^bind lb vserver (.*) ${srvcName}" > /dev/null 2>&1
			 if [ $? -ne 0 ]; then log_err "$srvcName can not be verified, thus deleting now..."; unset SERVICES["$srvcName"]; continue; fi
			 log_debug "33" "$(echo ${srvcName}_==_${SERVICES[$srvcName]})"
			 poolMembers+=("${srvcIP}:${srvcPort}:${srvName}:${srvcState}")
			 log_debug "34" "${poolMembers[$zz]}"
			 (( zz++ ))

		done
		
		unset srvcName srvName srvcType srvcPort monitorLine monName tempArry f s serviceArray
		log_debug "40" "$(declare -p SERVICES)"
		log_debug "41" "poolMembers Array : $(declare -p poolMembers)"
		log_debug "42" "sg_params: $(declare -p sg_params)"
		
		#sg_type a.k.a "type"
		log_debug "43" "Service Group Type : $type"
		
		monitor_sg[0]="${monitorName}"
		
			case ${monitor_sg[$mon]} in
	
					tcp|http|https|ftp|ping)
					#do Nothing for these predefined monitor types
					;;
					
					*)
						# Here, we are dealing with a custom definition monitor.
						createMonitor "${monitor_sg[0]}"
					;;
			esac

else

		# Read ServiceGroup and Type
		read sg type <<< $( echo "$file" | grep -E "^add serviceGroup " | awk '{ print $3" "$4 }' )
		log_debug "23" "SG ${sg}, TYPE ${type}, Server Array : $(declare -p servers)"
		# port numbers and monitor definition. Also get their status definition. "disable" or not
		# We store all values according to schema defined in createPoolv2() function which is => poolMembers[0]="${Service-IP}:${Service-Port}:${Server-Name}:${Service-State}"
		declare -a poolMembers
		read -a poolMembers <<< $( for i in "${!SERVERS[@]}"; do echo "$file" | grep -E "^bind serviceGroup ${sg} " | grep "$i" | sed -s 's,bind serviceGroup ,,g' | awk -v name="$i" -v ip="${SERVERS[$i]}" '{ if ($0 ~ /state\ DISABLED/) { print ip":"$3":"name":D" } else { print ip":"$3":"name":E" } }' | tr '\n' ' ' ;  done )
		log_debug "24" "poolMembers Array: $(declare -p poolMembers)"

fi


if [[ $ISSERVICE == FALSE ]]; then
# Try to find monitor name. If no monitor definition found, use default one
# Some vs definitions have more than one monitor.
		declare -a monitor_sg
		read -a monitor_sg <<< $( echo "$file" | grep -E "^bind serviceGroup $sg \-monitorName " | awk '{ print $5 }' | tr '\n' ' ' )
		log_debug "11" "Monitor: ${monitor_sg[@]}"
		if [ ${#monitor_sg[@]} -eq 0 ]; then
		    monitor_sg[0]="tcp"
		else

			for mon in "${!monitor_sg[@]}"
			do	

					case ${monitor_sg[$mon]} in

						tcp|http|https|ftp|ping)
						;;
						*)

						# Here, we are dealing with a custom definition monitor.
						createMonitor "${monitor_sg[$mon]}"
						;;

					esac

			done
		fi

fi
log_debug "17" "SG Name: ${sg},  SG-TYPE: ${type}, $( declare -p servers )"

if [[ $ISSERVICE == FALSE ]]; then
		# Parse Service Group Parameters
		declare -a tmpArry
		declare -A sg_params
		while read -r line
		do
			tmpArry+=( "$line" )
		done <<< $( echo "$file" | grep "add serviceGroup $sg $type " | awk -F " $sg $type " '{ print $2 }' | sed -e 's,^-,,g;s, -,\n,g' )
		unset line
		log_debug "6" "service Group Params $(declare -p tmpArry)"
		for m in "${!tmpArry[@]}"
		do
			f=$( echo ${tmpArry[$m]} | awk '{ print $1 }' )
			s=$( echo ${tmpArry[$m]} | awk '{ print substr($0, index($0,$2)) }' ) 
			sg_params["$f"]="$s"
			log_debug "7" "$f -> ${sg_params[$f]}"
		done
		unset tmpArry
		log_debug "8" "Whole Parameter value list of service Group: $( declare -p sg_params )"
fi

# Try to parse "add lb verver" definiton and it's parameters 
# An example line is "add lb vserver ALM.Web_CSW SSL 0.0.0.0 0 -persistenceType SOURCEIP -timeout 30 -cltTimeout 180"
read -r lbVsrvName lbVsrvType vsIP vsPort <<< $( echo "$file" | grep -E "add lb vserver " | awk '{ print $4" "$5" "$6" "$7 }' )
if [ -z $lbVsrvName ]; then
	echo "Seems like this file don't have a valid \"add lb vserver\" definition"
	echo "You may want to check it"
	exit 44
fi

declare -A lbVsrvParams
declare -a tmpArry
while read -r line
do
	tmpArry+=( "$line" )
done <<< $( echo "$file" | grep -E "add lb vserver $lbVsrvName $lbVsrvType $vsIP $vsPort " | awk -F " $vsIP $vsPort " '{ print $2 }' | sed -e 's,^-,,g;s, -,\n,g' )
unset line
for x in "${!tmpArry[@]}"; do
	f=$( echo "${tmpArry[$x]}" | awk '{ print $1 }' )
	s=$( echo "${tmpArry[$x]}" | awk '{ print substr($0, index($0,$2)) }' )
	lbVsrvParams["$f"]="$s"
	log_debug "9" "$f -> ${lbVsrvParams[$f]}"
done
unset tmpArry
log_debug "10" "Whole Parameter list of LB VServer: $(declare -p lbVsrvParams)"

# Create Pool 
createPoolv2
# The Name of Virtual Server is ready
VSBODY[name]="${lbVsrvName}_vs"
[[ $vsPort == \* ]] && vsPort=0
VSBODY[destination]="${vsIP}:${vsPort}"
[[ ${vsIP} == "0.0.0.0" ]] && (( $vsPort != 0 )) && notes+=("Virt. Server Destination ${vsIP}:${vsPort}. Bu tip ANY:IP Forwarding tanimlara dikkat edilmeli.")
[[ ${vsIP} == "0.0.0.0" ]] && (( $vsPort == 0 )) && notes+=("Virt. Server Destination ${vsIP}:${vsPort}. Bu tip ANY:IP Forwarding tanimlara dikkat edilmeli.")
# Netscaler default types HTTP, FTP, TCP, UDP, SSL, SSL_BRIDGE, SSL_TCP, DTLS, NNTP
# DNS, DHCPRA, ANY, SIP_UDP, SIP_TCP, SIP_SSL, DNS_TCP, RTSP, PUSH, SSL_PUSH, RADIUS
# RDP, MYSQL, MSSQL, DIAMETER, SSL_DIAMETER, TFTP, ORACLE, SMPP, SYSLOGTCP, SYSLOGUDP
# FIX, SSL_FIX, PROXY, USER_TCP, USER_SSL_TCP, QUIC, IPFIX, LOGSTREAM, MONGO, MONGO_TLS
echo "${lbVsrvType}" | grep -iE "HTTP|FTP|TCP|SSL|SSL_BRIDGE|SSL_TCP|SIP_TCP|SIP_SSL|DNS_TCP|RTSP|PUSH|SSL_PUSH|RDP|MYSQL|MSSQL|DIAMETER|SSL_DIAMETER|SYSLOGTCP|SMPP|PROXY|USER_TCP|USER_SSL_TCP|IPFIX" > /dev/null 2>&1 
if [ $? -eq 0 ]; then
	F5VirtSrvType=tcp
else
	F5VirtSrvType=udp
fi
VSBODY[ip-protocol]="${F5VirtSrvType}"

if [[ ${sg_params[cip]} == ENABLED* ]] && ( [ $lbVsrvType == SSL ] || [ $lbVsrvType == HTTP ] ); then
    # There are a couple of different methods to carry client ip info through traffic
    # One of the easiest methods is storing this information in a http header.
    # So, here is a http profile which inserts a header in a http transaction.
	log_debug "21" "Creating a HTTP Profile client IP header insert and with server-agent-name zws"
	headerName=$(echo ${sg_params[cip]} | awk '{ print $2 }')
	http_profile=""
	if [[ $namingIteration ]]; then
		http_profileName="${lbVsrvName}_insert_${headerName}_http" # Http Profile names must be inserted with a pair of curl braces ( "{ }" ).
	else
		http_profileName="insert_${headerName}_http"
	fi
	http_profile=$( echo "ltm profile http /Common/${http_profileName} {" )
	http_profile=$( echo "$http_profile"; echo -e "    defaults-from /Common/http" )
	http_profile=$( echo "$http_profile"; echo -e "    header-insert \"${headerName}: [IP::remote_addr]\"" )
	http_profile=$( echo "$http_profile"; echo -e "    server-agent-name zws")
	[[ ${lbVsrvParams[redirectURL]} ]] && http_profile=$( echo "$http_profile"; echo -e "    fallback-host ${lbVsrvParams[redirectURL]}" ) #fallback-host https://www.google.com/
	http_profile=$( echo "$http_profile"; echo -e "}" )
	
	# After Completed of the http profile creations, we have to register it on our VsConstrction
	VSBODY[profiles]+="${http_profileName},"
	vsConstruct[profiles]+="${http_profile},"
	unset headerName http_profile http_profileName
	
elif [[ ${sg_params[cip]} == DISABLED ]] && ( [[ $lbVsrvType == SSL ]] || [[ $lbVsrvType == HTTP ]] ) && [[ ${VSBODY[ip-protocol]} == tcp ]]; then
	log_debug "21" "Creating a blank HTTP Profile with server-agent-name zws"
	
	http_profile=""
	if [[ $namingIteration ]]; then
		http_profileName="${lbVsrvName}_http" # Http Profile names must be inserted with a pair of curl braces ( "{ }" ).
		http_profile=$( echo "ltm profile http /Common/${http_profileName} {" )
		http_profile=$( echo "$http_profile"; echo -e "    defaults-from /Common/http" )
		http_profile=$( echo "$http_profile"; echo -e "    server-agent-name zws")
		[[ $( checkXFFRequire ) == TRUE ]] && http_profile=$( echo "$http_profile"; echo -e "    header-insert \"XFF: [IP::remote_addr]\"" ) # make an additional check for X-Forwarded-For Header
		[[ ${lbVsrvParams[redirectURL]} ]] && http_profile=$( echo "$http_profile"; echo -e "    fallback-host ${lbVsrvParams[redirectURL]}" ) #fallback-host https://www.google.com/
		http_profile=$( echo "$http_profile"; echo -e "}" )
		
		VSBODY[profiles]+="${http_profileName},"
		vsConstruct[profiles]+="${http_profile},"
		notes+=("Yeni isimle bos bir http profili olusturularak kullanıldı.")
	else
		http_profileName="http"
		
		VSBODY[profiles]+="${http_profileName},"
		notes+=("HTTP profili olarak standart default http profili kullanıldı.")
	fi

fi

# Client Side & Server Side TCP profiles.
if [[ ${VSBODY[ip-protocol]} == tcp ]] && ( (( ${lbVsrvParams[cltTimeout]} > 300 )) || (( ${sg_params[svrTimeout]} > 300 )) ); then
	
		tcpClientProfileName="${lbVsrvName}_client_tcp"
		clientTcpProfile="ltm profile tcp /Common/${tcpClientProfileName} {"
		clientTcpProfile=$( echo "$clientTcpProfile"; echo "    defaults-from /Common/tcp-wan-optimized" )
		clientTcpProfile=$( echo "$clientTcpProfile"; echo "    idle-timeout ${lbVsrvParams[cltTimeout]}" )
		clientTcpProfile=$( echo "$clientTcpProfile"; echo "}" )
	
		VSBODY[profiles]+="${tcpClientProfileName},"
		vsConstruct[profiles]+="${clientTcpProfile},"

		tcpServerProfileName="${lbVsrvName}_server_tcp"
		serverTcpProfile="ltm profile tcp /Common/${tcpServerProfileName} {"
		serverTcpProfile=$( echo "$serverTcpProfile"; echo "    defaults-from /Common/tcp-lan-optimized" )
		serverTcpProfile=$( echo "$serverTcpProfile"; echo "    idle-timeout ${sg_params[svrTimeout]}" )
		serverTcpProfile=$( echo "$serverTcpProfile"; echo "}" )

		VSBODY[profiles]+="${tcpServerProfileName},"
		vsConstruct[profiles]+="${serverTcpProfile},"
		
fi

# Compression aka "CMP == YES" in Service Group definition
if [[ ${sg_params[CMP]} == YES ]] && ( [[ $type == HTTP ]] || [[ $type == SSL ]] ) && ( [[ $lbVsrvType == HTTP ]] || [[ $lbVsrvType == SSL ]] ); then
	compression="httpcompression"
	VSBODY[profiles]+="${compression},"
	# Due to default compression profile attached here, we won't add any detail for it.
	notes+=("Default httpcompression profili kullanıldı.")
fi

# For Persistence and Fallback Persistence profiles
if [[ ${lbVsrvParams[persistenceType]} ]] && [[ ${lbVsrvParams[persistenceType]} != NONE ]]; then
	createPersistence
fi
[[ ${lbVsrvParams[persistenceBackup]} != "" ]] && { createFallbackPersistence; }

# Is USIP (-usip YES) enabled ?
# This means we have to turn off SNAT feature in F5 vs definiton.
log_debug "21" "USIP is ${sg_params[usip]} // SNAT -> automap"
if [[ ${sg_params[usip]} == "NO" ]]; then # this is used for only SNAT Auto-Map enable or disable. No Support for SNAT POOL !!! 
	VSBODY[snat-addr]="automap"
else
	notes+=("Dikkat: SNAT kapalı. Sunucuların default gw'i F5 olmalı ve sunucuların network'e erisebilmeleri için ANY tipinde bir VS olusturulmalı.")
fi

log_debug "22" "Service Group Type: ${type} & LB Vserver Type is ${lbVsrvType}"  

declare -a clientSSLProfiles
read -a clientSSLProfiles <<< $( echo "$file" | grep -E "^bind ssl vserver ${lbVsrvName} \-certkeyName " | awk -F "-certkeyName " '{ print $2 }' | cut -d " " -f1 | tr '\n' ' ' )
if [ ${#clientSSLProfiles[@]} -gt 0 ]; then
	log_debug "55" "$(declare -p clientSSLProfiles)"
	for clientSSLProfile in "${!clientSSLProfiles[@]}"
	do
		createClientSSLProfile "${clientSSLProfiles[$clientSSLProfile]}"
		log_debug "41" "ClientSSL Profile : ${vsConstruct[clientssl]}"
	done
fi
(( ${#clientSSLProfiles[@]} > 1 )) && notes+=("ClientSSL SNI yapılandırılması için bir ClientSSL profilinin default <sni-default true> olarak işaretlenmesi gerek.")
unset clientSSLProfiles clientSSLProfile

##### Server SSL Profile create
# bind ssl serviceGroup OBSD-3343-SSL-1 -certkeyName www.test1.com_key-cert
# May be there is no need to write below code but we believe it will help to cover all features 
declare -a serverSSLProfiles
read -a serverSSLProfiles <<< $( echo "$file" | grep -E "^bind ssl serviceGroup ${sg} \-certkeyName " | awk -F "-certkeyName " '{ print $2 }' | cut -d " " -f1 | tr '\n' ' ' )
countSGroupSSLParams=$(echo "$file" | grep -cE "ssl serviceGroup ${sg} " )
if [ ${#serverSSLProfiles[@]} -gt 0 ]; then
	log_debug "55" "$(declare -p serverSSLProfiles)"
	for serverSSLProfile in "${!serverSSLProfiles[@]}"
	do
		createServerSSLProfile "${serverSSLProfiles[$serverSSLProfile]}"
	done
	
elif [ ${#serverSSLProfiles[@]} -eq 0 ] && (( $countSGroupSSLParams > 0 )); then
	# So, there is a reason to add "serverssl-insecure-compatible" profile.
	VSBODY[profiles]+="serverssl-insecure-compatible,"
	notes+=("serverssl-insecure-compatible profili eklendi.")
fi
unset serverSSLProfiles serverSSLProfile

	
## for some of globally defined NS features, we use below functions to achieve similar setup on F5
if ( [[ $type == SSL ]] || [[ $type == HTTP ]] ) && ( [[ $lbVsrvType == HTTP ]] || [[ $lbVsrvType == SSL ]] ); then
	cachingProfile
	responseHeaderReplace
fi



# Final Stage
# Here we print out whole VSBODY in a predefined order.
# I hope this works. After printing VSBODY, we will continue with vsConstruct array
# and traverse it all through to the end. 
	#~ ltm virtual /Common/appdynamics_prod_http_vs {
	    #~ destination /Common/10.86.51.104:80
	    #~ fallback-persistence /Common/appdynamics_http_source-addr-persistence
	    #~ ip-protocol tcp
	    #~ mask 255.255.255.255
	    #~ persist {
	        #~ /Common/appdynamics_http_cookie-persistence {
	            #~ default yes
	        #~ }
	    #~ }
		#~ policies {
			#~ ZB_generic_policy { }
		#~ }
	    #~ pool /Common/selfcare_datapower_pool
	    #~ profiles {
	        #~ /Common/appdynamics_http_http { }
	        #~ /Common/appdynamics_http_oneconnect { }
	        #~ /Common/appdynamics_http_optimized-caching { }
	        #~ /Common/appdynamics_http_tcp-lan-optimized {
	            #~ context serverside
	        #~ }
	        #~ /Common/appdynamics_http_tcp-wan-optimized {
	            #~ context clientside
	        #~ }
	        #~ /Common/appdynamics_http_wan-optimized-compression { }
	    #~ }
	    #~ rules {
	        #~ /Common/automiccrm_url_redirect
	        #~ /Common/response_header_remove_server
	    #~ }
	    #~ source 0.0.0.0/0
	    #~ source-address-translation {
	        #~ type automap
	    #~ }
	    #~ translate-address enabled
	    #~ translate-port enabled
	#~ }

# VSBODY parts
echo "#----------------------------------------------------------------#"
echo "## Vs Config for $lbVsrvName ##"
echo "#----------------------------------------------------------------#"
log_debug "100" "VSBODY Array Contains: $(declare -p VSBODY)\n\n"
[[ ${VSBODY[name]} ]] && echo "ltm virtual /Common/${VSBODY[name]} {" && unset VSBODY[name]
[[ ${VSBODY[destination]} ]] && echo "    destination /Common/${VSBODY[destination]}" && unset VSBODY[destination]
[[ ${VSBODY[fallback]} ]] && echo "    fallback-persistence /Common/${VSBODY[fallback]}" && unset VSBODY[fallback]
[[ ${VSBODY[ip-protocol]} ]] && echo "    ip-protocol ${VSBODY[ip-protocol]}" && unset VSBODY[ip-protocol]
if [[ ! ${VSBODY[mask]} ]]; then
	echo "    mask 255.255.255.255" # Return here to investigate further about ipMASK & ipPATTERN values in NS
else
	echo "    mask ${VSBODY[mask]}"
	unset VSBODY[mask]
fi
[[ ${VSBODY[persist]} ]] && { echo "    persist {"; echo "        /Common/${VSBODY[persist]} {"; echo "            default yes"; echo "        }"; echo "    }"; } && \
	unset VSBODY[persist]
[[ ${VSBODY[policies]} ]] && { echo "    policies {"; echo "${VSBODY[policies]}" | sed -e 's/,$//g;s/,/\n/g' | \
	while read -r line
	do
		echo "        /Common/${line} { }"
	done
	echo "    }"; } && unset VSBODY[policies]
[[ ${VSBODY[pool]} ]] && echo "    pool /Common/${VSBODY[pool]}" && unset VSBODY[pool]
[[ ${VSBODY[profiles]} ]] && { echo "    profiles {"; echo "${VSBODY[profiles]}" | sed -e 's/,$//g;s/,/\n/g' | \
	while read -r line
	do
		if [[ ${line} =~ _clientssl$ ]] || [[ ${line} =~ _client_tcp$ ]]; then
			echo "        /Common/${line} {"; echo "            context clientside"; echo "        }"
		elif [[ ${line} =~ insecure-compatible$ ]] || [[ ${line} =~ serverssl$ ]] || [[ ${line} =~ _server_tcp$ ]]; then
			echo "        /Common/${line} {"; echo "            context serverside"; echo "        }"
		else
			echo "        /Common/${line} { }"
		fi
	done
	echo "    }"; } && unset VSBODY[profiles]
[[ ${VSBODY[rules]} ]] && { echo "    rules {"; echo "${VSBODY[rules]}" | sed -e 's/,$//g;s/,/\n/g' | \
	while read -r line
	do
		echo "        /Common/${line}"
	done
	echo "    }"; } && unset VSBODY[rules]
[[ ${VSBODY[source]} ]] && echo "    source ${VSBODY[source]}"
[[ ${VSBODY[snat-addr]} ]] && { echo "    source-address-translation {"; echo "        type ${VSBODY[snat-addr]}"; echo "    }"; } && unset VSBODY[snat-addr]
[[ ${VSBODY[translate-addr]} ]] && echo "    translate-address ${VSBODY[translate-addr]}"
[[ ${VSBODY[translate-port]} ]] && echo "    translate-port ${VSBODY[translate-port]}"
echo "}" # This is the final curly brace of VSBODY

echo "#----------------------------------------------------------------#"
if [ ${#VSBODY[@]} -eq 0 ]; then
	echo -e "#### There is no remaining parts, all clean ####"
else
	echo -e "#----------------------------------------------------------------#"
	echo "# There is/are ${#VSBODY[@]} remaining parts here #"
	echo "#----------------------------------------------------------------#"
	for part in "${!VSBODY[@]}"
	do
	   echo "$part -> ${VSBODY[$part]}"
	done
	
fi
echo "#----------------------------------------------------------------#"
if [ ${#vsConstruct[@]} -ne 0 ]; then
	echo -e "#### The other profile definitions ####"
	echo "#----------------------------------------------------------------#"
	for part in "${!vsConstruct[@]}"
	do
		if [[ ${vsConstruct[$part]} =~ }, ]]; then
			echo -e "### ${part}::\n${vsConstruct[$part]}" | sed -e "s/},/}\n/g"
		elif [[ ${vsConstruct[$part]} =~ , ]];then
			echo -e "### ${part}::\n${vsConstruct[$part]}" | sed -e "s/,/\n/g"
		else
			echo -e "### ${part}::\n${vsConstruct[$part]}"
		fi
	done

else 
	echo "Seems like there is no additional profiles, weird..."
fi
echo "#-------------------------- ver:${version} ----------------------------#"
echo "#****************************************************************#"
echo "#                             NOTES                              #"
echo "#                                                                #"
for i in "${!notes[@]}"
do
	echo "(*) ${notes[$i]}" | fold -b68
done
echo "#                                                                #"
echo "#****************************************************************#"
