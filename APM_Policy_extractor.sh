#!/bin/bash
#
#	APMPolicyBuilder: This script takes an APM profile name as an argument along with related bigip.conf file and
#			 provides whole policy chain recursively. It's designed as a separate project and it is capable to provide related 
#			 ltm rules even if they used as "Agent-ID" mechanism. Also, this script collect all related customized profiles 
#			 and make a compressed (xz) tar archive from them. The tar archive could be found in same directory you run this script.
#			 The name "APM-Customizations_${APM-Policy-Name}.tar.xz".
#
#			 When script run and finish its job, you can find APM-Policy and all related policies in a file in same directory you ran
#			 this script. The file name is "./APM-Policy_${APM-Policy-Name}"
#
#	Caution: It's better you run this script in the directory where extracted of Qkview or UCS file, because all files store in
#			 that directory and we never know where to look for those files.
#
#	Fatih Celik : 2020-Dec-30
#

##### Global Variables #####
DATE=$(date +%Y-%m-%d)
RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'
DEBUG=1
version="v0.9.3"

HEADER="
# 	Version = $version
#	Date	= $DATE
#	Policy	= "$1"
#
# You can use below lines to load whole configuration, but before going
# further you must be aware of that there are two distict part of any
# APM policy. The APM policies contains related profiles and the customizations
# made for this policy. The customizations are normally stored in separated files
# under /config/ directory and here you can find them in a tar.xz archive file.
# You have to unzip tar.xz archive and put all customizations under the config 
# directory on F5. After then, you try to load the rest of the content stored
# in this file. Good lucks, because you'll need it...
#
"

findEnd(){
# count every opening and closing curly brace and find out where it ends...
	
	if [ $# -eq 1 ] && [ "$1" == "-e" ]; then
	
		i=1
		openCurly=0
		while read -r line
		do
			isCurly=$(echo $line | grep -E "{|}" )
			if [ "$isCurly" ]; then
				openCurly=$(( openCurly + $(echo $line | sed 's/[^{]//g' | tr -d '\n' | wc -m) ))
				openCurly=$(( openCurly - $(echo $line | sed 's/[^}]//g' | tr -d '\n' | wc -m) ))	
				if [ $openCurly -eq 0 ]; then
					echo "$line"
					exit 0
				fi
			fi
			echo "$line"
			(( i+=1 ))
		done < <( cat - ) 
		
	elif [ $# -eq 2 ]; then
	
		i=1
		openCurly=0
		file=$1
		start=$2
		while read -r line
		do
			isCurly=$(echo $line | grep -E "{|}" )
			if [ "$isCurly" ]; then
				openCurly=$(( openCurly + $(echo $line | sed 's/[^{]//g' | tr -d '\n' | wc -m) ))
				openCurly=$(( openCurly - $(echo $line | sed 's/[^}]//g' | tr -d '\n' | wc -m) ))	
				if [ $openCurly -eq 0 ]; then
					endingLine=$i		
					echo $endingLine
					exit 0
				fi
			fi
			(( i+=1 ))
		done < <( /usr/bin/tail -n +${start} $file ) 
		
	elif [ $# -ne 2 ] && [ "$1" != "-e" ]; then
	
		i=1
		openCurly=0
		while read -r line
		do
			isCurly=$(echo $line | grep -E "{|}" )
			if [ "$isCurly" ]; then
				openCurly=$(( openCurly + $(echo $line | sed 's/[^{]//g' | tr -d '\n' | wc -m) ))
				openCurly=$(( openCurly - $(echo $line | sed 's/[^}]//g' | tr -d '\n' | wc -m) ))	
				if [ $openCurly -eq 0 ]; then
					endingLine=$i		
					echo $endingLine
					exit 0
				fi
			fi
			(( i+=1 ))
		done < <( cat - ) 
	fi
}
log_err() {
    msg=$1
    date=$(date +%F:%X)
    echo -e "[${date}][${RED}ERR${NC}] APMPolicyBuilder: ${version} ${RED}${msg}${NC}" 1>&2
}
log_info() {
    msg=$1
    #~ date=$(date +%F:%X)
    #~ echo -e "[${date}][${BLUE}INF${NC}] APMPolicyBuilder: ${msg}"
    echo -e "[${BLUE}INF${NC}] APMPolicyBuilder: ${msg}"
}
log_debug() {
    if (( ${DEBUG} == 1 )); then
		code=$1
        msg=$2
        #~ date=$(date +%F:%X)
        #~ echo -e "[${date}][${YELLOW}DBG${NC}] APMPolicyBuilder: ${msg}" 1>&2
        echo -e "[${YELLOW}DBG-${code}${NC}] APMPolicyBuilder: ${msg}" 1>&2
    fi
}
populateiRuleArry(){
	declare -a tmpArry
	local rule startingLine endingLine ruleName i=0
	
	read -a tmpArry <<< $( grep -nE "^ltm rule /" "${configFile}" | sed -e 's,ltm rule \/[a-zA-Z0-9\-\_]\+\/,,g;s, {,,g' | tr '\n' ' ' )
	for i in "${!tmpArry[@]}"
	do
		startingLine=$( echo "${tmpArry[$i]}" | cut -d ":" -f 1 )
		if (( $i == $(( ${#tmpArry[@]} -1 )) )); then
			endingLine=$(( $( tail -n +${startingLine} "${configFile}" | findEnd ) + $startingLine -1 )) 
		else
			endingLine=$(( $( echo "${tmpArry[$(($i+1))]}" | cut -d ":" -f 1 ) -1 ))
		fi
		ruleName=$(echo "${tmpArry[$i]}" | cut -d ":" -f 2)
		iRuleArry[$i]="${ruleName}:${startingLine}:${endingLine}"
	done

	log_debug "050" "iRuleArry: $(declare -p iRuleArry)"
}
findiRuleWithSequence(){
	# Apm could invoke an iRule with Agent_id functionalities.
	# This function takes agent-id and find its iRule.
	(( ${#iRuleArry[@]} == 0 )) && populateiRuleArry
	local lookup="$1" i=0 s1 e1 ruleName seq="$2" tmp

	for i in "${!iRuleArry[@]}"
	do
		IFS=":" read -r ruleName s1 e1 <<< $( echo "${iRuleArry[$i]}" )
		if (( $( sed -n "${s1},${e1}p" "${configFile}" | grep -c "$lookup" ) != 0 )); then
			checkListwithSequence "${s1},${e1}"
			[ $? -eq 0 ] && APM+=("${seq}:${s1},${e1}")
		fi
	done
}
findiRule(){
	# Apm could invoke an iRule with Agent_id functionalities.
	# This function takes agent-id and find its iRule.
	(( ${#iRuleArry[@]} == 0 )) && populateiRuleArry
	local lookup="$1" i=0 s1 e1 ruleName

	for i in "${!iRuleArry[@]}"
	do
		IFS=":" read -r ruleName s1 e1 <<< $( echo "${iRuleArry[$i]}" )
		if (( $( sed -n "${s1},${e1}p" "${configFile}" | grep -c "$lookup" ) != 0 )); then
			APM+=("${s1},${e1}")
		fi
	done
}
poolFind(){
	local poolName="$1" s1 e1 seq="$2"
	log_info "Looking for pool <${poolName}>"
	s1=$( grep -nE "^ltm pool (.*)${poolName} " "$configFile" | cut -d ":" -f1 )
	e1=$( tail -n +${s1} "$configFile" | findEnd )
	APM+=("${seq}:${s1},$(( $s1 + $e1 -1 ))")
	echo "PoolFound $poolName"
	
}
parsePolicyWithSequence(){
	# Recursive parsing function to parse all policy objects top to down.
	# The function requires a parameter which is the name of policy we are looking for.
	local lookup="$1" e1 policy ruleName tmp seq="$2" k
	declare -a starts
	declare -a tmpArry
	log_info "Looking for $lookup policy object"

	read -a starts <<< $( grep -nE "^(apm|ltm|sys) (.*)${lookup} " "$configFile" | cut -d ":" -f1 | tr '\n' ' ' )
	if [ ${#starts[@]} -eq 0 ]; then
		MISSING+=("${lookup}")
		return 0
	fi ## Here we can put an exception becouse sometimes nothing can be found.
	for k in "${!starts[@]}"
	do
		e1=$( tail -n +${starts[$k]} "$configFile" | findEnd )
		policy=$( sed -n ${starts[$k]},$(( ${starts[$k]} + $e1 -1 ))p "$configFile" )
		tmp="${starts[$k]},$(( ${starts[$k]} + $e1 -1 ))"
		checkListwithSequence "$tmp"
		if (( $? == 1 )); then

			log_info "This Policy ${lookup} <${tmp}> is already found and stored"
			return 33

		else

			APM+=("${seq}:${tmp}")
			log_debug "030" "The policy found \"${lookup}\" ${seq} -> ${starts[$k]}:${e1}, now looking for other related sub profiles called by it."
			if [[ $policy =~ agent\ irule-event ]]; then
				ruleName=$( echo "$policy" | grep "id " | awk -F "id " '{ print $2 }' )
				[[ -n $ruleName ]] && findiRuleWithSequence "$ruleName" $seq
			elif [[ $policy =~ cache-path ]]; then
				CUSTOMIZATIONS+=( "$( echo "$policy" | grep cache-path | awk -F "/" '{ print $NF }' )" )
			elif [[ $policy =~ \ pool\  ]]; then
				poolFind $( echo "$policy" | grep " pool " | awk -F " pool " '{ print $2 }' ) $seq
			fi
			read -ra tmpArry <<< $( echo "$policy" | grep -E "\/Common\/" | grep -v "    defaults-from " | tail -n +2 | awk '{ for (m=1; m<=NF; m++) if ($m ~ /\/Common\// ) print $m }' | tr '\n' ' ' )
			if [ ${#tmpArry[@]} -ne 0 ]; then
				log_debug "031" "tmpArry := $(declare -p tmpArry)"
				for p in "${!tmpArry[@]}"
				do
					log_debug "032" "Recursive Lookup for ${tmpArry[$p]}"
					parsePolicyWithSequence "${tmpArry[$p]}" $(( seq += 1 ))
				done
			fi
		fi
	done
}
parsePolicy(){
	# Recursive parsing function to parse all policy objects top to down.
	# The function requires a parameter which is the name of policy we are looking for.
	local lookup="$1" s1 e1 policy ruleName tmp
	declare -a tmpArry
	log_info "Looking for $lookup policy object"

	s1=$( grep -m1 -nE "^(apm|ltm rule) (.*)${lookup} " "$configFile" | cut -d ":" -f1 )
	if [ -z $s1 ]; then
		findiRule "${lookup}"
		return 0
	fi ## Here we can put an exception becouse sometimes nothing can be found.
	e1=$( tail -n +${s1} "$configFile" | findEnd )
	policy=$( sed -n ${s1},$(($s1 + $e1 -1))p "$configFile" )
	tmp="${s1},$(( $s1 + $e1 -1 ))"
	checkList "$tmp"
	if (( $? == 1 )); then
	
		log_info "This Policy is already found and stored"
		return 33

	else
	
		APM+=("$tmp")
		log_debug "030" "Policy found \"${lookup}\" ${s1}:${e1}"
		read -ra tmpArry <<< $( echo "$policy" | grep -E "\/Common\/" | tail -n +2 | awk '{ for (m=1; m<=NF; m++) if ($m ~ /\/Common\// ) print $m }' | tr '\n' ' ' )
		if [[ $policy =~ agent\ irule-event ]]; then
			ruleName=$( echo "$policy" | grep "id " | awk -F "id " '{ print $2 }' )
			tmpArry+=("$ruleName")
		elif [[ $policy =~ cache-path ]]; then
			CUSTOMIZATIONS+=( "$( echo "$policy" | grep cache-path | awk -F "/" '{ print $NF }' )" )
		fi
		log_debug "031" "tmpArry := $(declare -p tmpArry)"
		if [ ${#tmpArry[@]} -ne 0 ]; then
	
			for p in "${!tmpArry[@]}"
			do
				log_debug "032" "Recursive Lookup for ${tmpArry[$p]}"
				parsePolicy "${tmpArry[$p]}"
			done
		fi
	fi
}
checkList(){
	# Check we already found same object before. If so, we do not need to go further.
	local lookup="$1" i
	log_debug "080" "The amount of objects stored in APM is ${#APM[@]}"
	
	for i in "${!APM[@]}"
	do
		[[ ${APM[$i]} == $lookup ]] && return 1
	done
	
	return 0
}
checkListwithSequence(){
	# Check we already found same object before. If so, we do not need to go further.
	local lookup="$1" i
	log_debug "080" "The amount of objects stored in APM is ${#APM[@]}"
	
	for i in "${!APM[@]}"
	do
		[[ ${APM[$i]//*:} == $lookup ]] && return 1
	done
	
	return 0
}
collectAllPolicy(){
	# Print Whole policy objects and eliminate duplicates
	# make sure you store starting and exact ending line numbers in array "APM[]"
	# Make a tar archive from all customization profiles.
	local line

	log_info "Printing Whole APM policy and it's related objects into the file ${outFile}"
	echo "${APM[*]}" | tr ' ' '\n' | sort -nu | while read -r line
	do
		sed -n ${line}p "${configFile}"
	done >> "$outFile"
	
	log_info "Printing all customizations"
	echo "${CUSTOMIZATIONS[@]}" | tr ' ' '\n' | sort -u | while read -r line
	do
		find . -type f -name "${line}" -exec tar uf ./APM-Customizations_${lookupProfile}.tar {} \;
	done
	tar uf ./APM-Customizations_${lookupProfile}.tar "$outFile" && xz ./APM-Customizations_${lookupProfile}.tar
	
}
collectAllPolicyWithSequence(){
	# Print Whole policy objects and eliminate duplicates
	# make sure you store starting and exact ending line numbers in array "APM[]"
	# Make a tar archive from all customization profiles.
	local line

	log_info "Printing Whole APM policy and it's related objects into the file ${outFile}"
	log_debug "100" "Whole APM Policies : $(declare -p APM | tr ' ' '\n' )"
	echo "${APM[*]}" | tr ' ' '\n' | sort -n -t":" -k1 | uniq | while read -r line
	do
		echo "## ${line//:*} ##"
		sed -n ${line//*:}p "${configFile}"
		log_debug "101" "DEBUG ${line} DEBUG"
	done >> "$outFile"

	log_info "Printing all customizations"
	echo "${CUSTOMIZATIONS[@]}" | tr ' ' '\n' | sort -u | while read -r line
	do
		find . -type f -name "${line}" -exec tar uf ./APM-Customizations_${lookupProfile}.tar {} \;
	done
	tar uf ./APM-Customizations_${lookupProfile}.tar "$outFile" && xz ./APM-Customizations_${lookupProfile}.tar

}
### main()
declare -a iRuleArry

if [ $# -lt 2 ]; then
	log_err	"Can't find neither APM policy name nor bigip.conf"
	log_info "Seems like you need a little guidance"
	log_info "While invoking this script, you need to provide at least two information,"
	log_info "which are; APM_Policy_name (without \"/Common/\" prefix) and the path of the \"bigip.conf\" file"
	log_info "Usage:"
	log_info "APMPolicyBuilder.sh APM_POLICY_NAME BIGIP.CONF"
	
	exit 44;
fi
if [ -a "$2" ]; then
	
	declare -a APM
	declare -a CUSTOMIZATIONS
	declare -a MISSING
	lookupProfile="$1"
	configFile="$2"
	outFile="./APM-Policy_${lookupProfile}"

	startingLine=$( grep -nE "^apm policy (.*)${lookupProfile} " "${configFile}" | cut -d ":" -f 1 )
	if [ -z ${startingLine} ]; then
		echo "Looks like the APM policy doesn't exist, quitting"
		exit 12
	fi
	endingLine=$( tail -n +${startingLine} ${configFile} | findEnd )
	log_debug "001" "Starting = ${startingLine}, Ending = ${endingLine}"
	tmpObj="${startingLine},$(( $startingLine + $endingLine -1 ))"
	Policy=$( sed -n ${tmpObj}p $configFile ) # Also save the original policy so we can process it.

	# Starting to parse first APM policy
	
	for _policy in $( echo "$Policy" | awk '{ for (i=1; i <= NF; i++) if ($i ~ /\/Common\// ) print $i }' | tail -n +2 )
	do
		log_debug "003" "Looking for policy $_policy and its related policies."
		parsePolicyWithSequence "$_policy" 1
	done

	(( ${#MISSING[@]} )) && { log_info "There are missing objects"; declare -p MISSING | tr ' ' '\n'; }
	# Printing APM Policy and related APM Profile.
	startingLine=$( grep -nE "^apm profile (.*)${lookupProfile} " "${configFile}" | cut -d ":" -f 1 )
	endingLine=$( tail -n +${startingLine} ${configFile} | findEnd )
	echo "" > "${outFile}"
	[[ -n $HEADER ]] && echo "$HEADER" >> "${outFile}"
	sed -n "${startingLine},$(( $startingLine + $endingLine -1 ))p" "$configFile" >> "${outFile}"
	echo "$Policy" >> "$outFile"
	collectAllPolicyWithSequence

	unset Policy APM endingLine startingLine outFile configFile lookupProfile tmpObj
else 
	log_err "The $2 file is not accessible or don't exist." 
fi
