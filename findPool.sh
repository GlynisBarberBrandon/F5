#!/bin/bash 
file="$1"
poolName="$2"

if [ $# -lt 2 ]; then
    echo "Usage: findPool.sh  /Path/of/bigip.conf  PoolName"
    exit 5
fi

start=$(grep -n -E "^ltm rule /" ${file} | head -n 1 | cut -d ":" -f1)
lastRule=$(grep -n -E "^ltm rule /" ${file} | tail -n 1 | cut -d ":" -f1)
end=$(grep -n -E "^ltm (.*) /" ${file} | grep -A1 "${lastRule}" | tail -n 1 | cut -d ":" -f 1 )
end=$(( end -1 ))

declare -a arry
read -a arry <<< $( sed -n ${start},${end}p ${file} | grep -n -E "$poolName" | cut -d ":" -f1 | tr '\n' ' ')
if (( ${#arry[@]} )); then

    declare -a rulesArry
    read -a rulesArry <<< $( grep -n -E "^ltm rule /" ${file} | cut -d ":" -f1 | tr '\n' ' ' )
    rulesArry+=("$end")

    for i in "${!arry[@]}"
    do
        arry[$i]=$(( ${arry[$i]} + $start ))
        for m in "${!rulesArry[@]}"
        do
            if (( ${arry[$i]} > ${rulesArry[$m]} )) && (( ${arry[$i]} < ${rulesArry[$m +1]} )); then
                #echo "Found    ${rulesArry[$m]} ${arry[$i]} ${rulesArry[$m +1]}"
                sed -n "${rulesArry[$m]},${rulesArry[$m +1]}p" ${file} | head -n 1 | sed -e 's/ {$//g'
            fi
        done

    done

else

    echo "No Match Found in iRules"

fi

