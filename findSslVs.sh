#!/bin/bash

confFile="$1"

read -a clientssl <<< $( grep -E "ltm profile client-ssl" config/bigip.conf | awk '{ print $4 }' | tr '\n' ' ' )
read -a vslist <<< $( grep -nE "ltm virtual " "$confFile" | sed -e 's,ltm virtual ,,g;s, {$,,g' | tr '\n' ' ')


findFinish(){
#!/bin/bash
# count every opening and closing curly brace and find out where it ends...

if [ $# -ne 2 ]; then

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

else 

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


fi

}	

#~ echo " :DEBUG:"
#~ declare -p clientssl | tr ' ' '\n'
#~ echo " :DEBUG:" 
#~ declare -p vslist | tr ' ' '\n'
#~ echo "------"
declare -a found
for (( i = 0; i < ${#vslist[@]}; i++)){
	start=$( echo ${vslist[i]} | awk -F':' '{ print $1 }' )
	end=$( echo ${vslist[i+1]} | awk -F':' '{ print $1 -1 }' )
	name=$( echo ${vslist[i]} | awk -F':' '{ print $2 }' )
	# Last Item
	if (( $i == (${#vslist[@]} -1) )); then
		res=$(findFinish ${confFile} $start)
		end=$(( $res + $start -1 ))
	fi
	
	vsDef=$( sed -n ${start},${end}p "$confFile" )
	r=0
	for m in "${!clientssl[@]}"
	do
		echo "$vsDef" | grep "${clientssl[m]}" > /dev/null 2>&1
		if [ $? -ne 0 ]; then
			continue
		else
			found+=($i)
			r=1
			break
		fi
	done
	if [ $r -eq 0 ]; then
		echo "$vsDef" | grep "clientssl " > /dev/null 2>&1
		[ $? -eq 0 ] && found+=($i) 
	fi
}

for m in "${!found[@]}"
do
	unset vslist[${found[$m]}]	
done

vslist=("${vslist[@]}")
echo "#######################################################"
echo "There are ${#vslist[@]} virtual servers which don't have any Client-SSL profile"
declare -p vslist | tr ' ' '\n' | sed -e 's,\"[0-9]\+\:,\",g'
echo "#######################################################"
echo "#######################################################"
