#!/bin/bash

set -e

__ScriptVersion="3.0"

so=$1 #"libc++_shared.so" # It can be inject repeatedly

gadget="libYJ.so"
python="python3.9"
pip="pip3"

#behave="script" #listen
behave="listen" #script
script_path="/sdcard/explore.js"

load_type="resume" #wait

unset fversion
config_file=${gadget%.*}.config.so

main(){
	fversion=$(frida --version)
	if [ ! -f $gadget ];then
		wget https://github.com/frida/frida/releases/download/${fversion}/frida-gadget-${fversion}-android-arm64.so.xz
		unxz -d frida-gadget-${fversion}-android-arm64.so.xz
		mv frida-gadget-${fversion}-android-arm64.so $gadget
	fi
	#useApktool
	#mv $target/lib/arm64-v8a/$so .

	toPython

	#cp $gadget $so $target/lib/arm64-v8a/
	#./apktool b $target
	#mv $target/dist/$target.apk out.apk
	#if [ ! -f uber-apk-signer-1.3.0.jar ];then
	#	wget https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar
	#fi
	#java -jar uber-apk-signer-1.3.0.jar -a out.apk
	echo "readelf -d $so | grep frida"
	#echo "adb install out-aligned-debugSigned.apk"
	configuration
	adb push $so /sdcard/
	adb push $gadget /sdcard/
	adb push $config_file /sdcard/
	echo -e "\033[32m$so $gadget $config_file has been adb put into /sdcard/ \033[0m"
}

configuration(){
	echo "{" > ${config_file}
	echo "  \"interaction\": {" >> ${config_file}
	if [ "$behave" == "script" ];then
		echo "    \"type\": \"script\"," >> ${config_file}
		echo "    \"path\": \"$script_path\"" >> ${config_file}
		gernerate_explore
	else
		echo "    \"type\": \"listen\"," >> ${config_file}
		echo "    \"address\": \"127.0.0.1\"," >> ${config_file}
		echo "    \"port\": \"27042\"," >> ${config_file}
		echo "    \"on_port_conflict\": \"fail\"," >> ${config_file}
		echo "    \"on_load\": \"$load_type\"" >> ${config_file}
	fi
	echo "  }" >> ${config_file}
	echo "}" >> ${config_file}
}


log(){
	if [ $# -gt 1 ];then
		printf "\033[31mParameter can only be one!!!" >& 2;exit;fi
	tty_wid=$(tput cols)
	line=$(printf "\033[33m%00${tty_wid}d\n" 0 | tr "0" "=")
	string_len=$(echo $1 | wc -c)
#	((tty_wid -= string_len))
#	((tty_wid /= 2))
	echo $line
	printf "%00${tty_wid}d" 0 | tr "0" " "
	printf "\033[91m$1\n"
	echo -e "$line\033[0m"
}

gernerate_explore(){
	adb push ./explore.js /sdcard/
	log "Target App must have read and write access, Views the logger through \"adb shell 'tail -f /sdcard/yj.log' \" after running the App"
}


toPython(){
	$pip show lief > /dev/null
	if [ $? != 0 ];then
			$pip install lief
	fi
	$pip show lief > /dev/null
	if [ $? != 0 ];then
		echo -e "\033[31m Can't install life by pip\033[0m"
		exit
	fi
	echo "aW1wb3J0IGxpZWYKaW1wb3J0IHN5cwpsaWJuYXRpdmUgPSBsaWVmLnBhcnNlKHN5cy5hcmd2WzFdKQpsaWJuYXRpdmUuYWRkX2xpYnJhcnkoc3lzLmFyZ3ZbMl0pCmxpYm5hdGl2ZS53cml0ZShzeXMuYXJndlsxXSkK" | base64 -d > inject.py
	$python inject.py $so $gadget
	rm ./inject.py
}

#useApktool(){
#	if [ ! -f apktool ];then
#		wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/osx/apktool
#		chmod +x apktool
#	fi
#	if [ ! -f apktool.jar ];then
#		wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar
#		mv apktool_2.7.0.jar apktool.jar
#		chmod +x apktool.jar
#	fi
#
#	#-rs is to not decode resources and sources
#	./apktool d -rs $target.apk
#}


usage (){
	echo "Usage :  $0 [options] [--] targetLib gadgetInteractionType[option]

	targetLib such as             ->  libc++_shared.so
	gadgetInteractionType such as ->  script or listen

	inject.sh execution mode E.g : \"bash inject.sh ./libc++_shared.so listen\"

    Options:
    -h|help       Display this message
    -v|version    Display script version
    -c|clean      Remove other file

	If used script mode target App must have read and write access, Views the logger through \"adb shell 'tail -f /sdcard/yj.log' \" after running the App(default script is the /sdcard/explore.js in the phone pushed by the local explore.js file)"
}

#  Handle command line arguments
while getopts ":hvc" opt;do
  case $opt in
	h|help)			usage; exit 0   ;;
	v|version)	echo "$0 -- Version $__ScriptVersion"; exit 0   ;;
	c|clean)		mv $(ls | grep -v "explore.js\|inject.sh") /tmp/ ; exit ;;
	* )					echo -e "\n  Option does not exist : $OPTARG\n"
							usage; exit 1   ;;
  esac
done
shift $(($OPTIND-1))


if [ -z "$1" ];then
	echo -e "\033[31m"Try -\> bash inject.sh [libc++_shared.so]?"\033[0m"
	exit
elif [ "${1##*.}" != "so" ];then
	echo -e "\033[31m"Try -\> bash inject.sh [libc++_shared.so]?"\033[0m"
	exit
fi

if [[  "$2" == "script" || "$2" == "listen" ]];then
	behave="$2"
fi



main
