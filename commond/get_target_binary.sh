#!/bin/sh
if [ $# == 0 ];then
	echo "no target binary !!!"
	exit 1
elif [ $# == 1 ];then 
	echo "no lib !!!"
	exit 1
fi


target_binary_path=$1  
lib_name=$2
ROW_NUMBER=$3
OFFSET=$4

YJ_dir=".YJ"
obj="objdump"

#Check OS System 
if [ "$(uname)" == "Darwin" ];then #Mac
	obj="objdumps"	
elif [ "$(uname)" == "Linux" ];then #Linux
	obj="objdump"
else
	echo "Windows has not been tested for the time being"
	exit 1
fi

#Checkout is intall objdump(Must be objdump under linux)
if [ ! -x "$(command -v $obj)" ];then
	echo "Please Install Linux objdump,Mac -> (brew install binutils)"
	echo "And renamed it to $obj"
	exit 1
fi

#is exist .yj dir?
if [ ! -d "$YJ_dir" ];then
	mkdir $YJ_dir
	adb pull $target_binary_path $YJ_dir/  
	$obj "$YJ_dir/$lib_name" -j .text -S > "$YJ_dir/$lib_name.asm"
	exit 1
#is exist lib file?
elif [ ! -f "$YJ_dir/$lib_name" ];then
	adb pull $target_binary_path $YJ_dir/  
	$obj "$YJ_dir/$lib_name" -j .text -S > "$YJ_dir/$lib_name.asm"
	exit 1
#is exist asm file?
elif [ ! -f "$YJ_dir/$lib_name.asm" ];then
	$obj "$YJ_dir/$lib_name" -j .text -S > "$YJ_dir/$lib_name.asm"
	exit 1
else
	grep -C $ROW_NUMBER $OFFSET "$YJ_dir/$lib_name.asm" | awk '{$2="";print 0x$0}'
	exit 1
fi

