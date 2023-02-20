#!/bin/bash
__ScriptVersion="3"

snapshot_dir=".snapshot"

main(){
	# Use system tools md5
	md5_count=0

	if [ ! -d "$snapshot_dir" ];then
		mkdir $snapshot_dir
	fi

	for file in $*;do
		if [[ ! -f ${snapshot_dir}/$(basename $file).md5 || `cat ${snapshot_dir}/$(basename $file).md5` != `md5 -q $file` ]];then
			md5 -q $file > ${snapshot_dir}/$(basename $file).md5
			((md5_count++))
		fi
	done
	echo -n $md5_count
}

clean(){
	if [ -d $snapshot_dir ];then
		mv $snapshot_dir /tmp/snapshot-`date +"%Y%m%d%H%M%S"`
	fi
}

usage (){
	echo "Usage :  $0 [options] [--]

    Options:
    -h|help       Display this message
    -v|version    Display script version"

}

#  Handle command line arguments
while getopts ":hvc" opt;do
  case $opt in
	h|help)			usage; exit 0   ;;
	v|version)	echo "$0 -- Version $__ScriptVersion"; exit 0   ;;
	c|clean)		clean; exit 0   ;;
	* )					echo -e "\n  Option does not exist : $OPTARG\n"
							usage; exit 1   ;;
  esac
done
shift $(($OPTIND-1))

main $*
