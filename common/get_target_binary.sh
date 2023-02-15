#!/bin/bash

__ScriptVersion="1.0"

YJ_dir=".YJ"
obj="objdump"

target_binary_path=$1
lib_name=$2
ROW_NUMBER=$3
OFFSET=$4

main(){
	if [ $# -lt 4 ];then usage; fi

	if [ ! -x "$(command -v $obj)" ];then
		echo -e "\033[31m Don't found objdump !!! \033[0m";exit;fi

	#is exist .yj dir?
	if [ ! -d "$YJ_dir" ];then
		mkdir $YJ_dir
		adb pull $target_binary_path $YJ_dir/
		$obj "$YJ_dir/$lib_name" --no-show-raw-insn -j .text -S > "$YJ_dir/$lib_name.asm"
		exit
		#is exist lib file?
	elif [ ! -f "$YJ_dir/$lib_name" ];then
		adb pull $target_binary_path $YJ_dir/
		$obj "$YJ_dir/$lib_name" --no-show-raw-insn -j .text -S > "$YJ_dir/$lib_name.asm"
		exit
		#is exist asm file?
	elif [ ! -f "$YJ_dir/$lib_name.asm" ];then
		$obj "$YJ_dir/$lib_name" --no-show-raw-insn -j .text -S > "$YJ_dir/$lib_name.asm"
		exit
	else
		grep -i -C $ROW_NUMBER " $OFFSET:" "$YJ_dir/$lib_name.asm"
	fi
}


usage (){
	echo "Usage :  $0 [options] [--]

	Options:
	-h|help       Display this message
	-v|version    Display script version

	Check parameters $0 [target_binary_path_so] [so name] [display row] [address offset]

	Such as -> $0 /data/app/com.xx/lib/arm64/xx.so xx.so 5 f6978"
}

#  Handle command line arguments
while getopts ":hv" opt;do
	case $opt in
		h|help)			usage; exit 0   ;;
		v|version)	echo "$0 -- Version $__ScriptVersion"; exit 0   ;;
		* )					echo -e "\n  Option does not exist : $OPTARG\n"
			usage; exit 1   ;;
	esac
done
shift $(($OPTIND-1))

main $@
