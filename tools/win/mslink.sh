#!/bin/bash

#############################################################################################
# mslink.sh v1.2
#############################################################################################
# This script is used to create a Windows Shortcut (.LNK file)
# Script created based on the doc
#   http://msdn.microsoft.com/en-us/library/dd871305.aspx
# Source: http://www.mamachine.org/mslink/index.en.html
# (translated to english by me/Google Translate)
#############################################################################################

OPTIONS=$(getopt -q -n ${0} -o hpl:o:n:w:a:i: -l help,lnk-target:,output-file:,name:,working-dir:,arguments:,icon:,printer-link -- "$@")

eval set -- ${OPTIONS}

IS_PRINTER_LNK=0
while true; do
  case "$1" in
    -h|--help) HELP=1 ;;
    -p|--printer-link) IS_PRINTER_LNK=1 ;;
    -l|--lnk-target) LNK_TARGET="$2" ; shift ;;
    -o|--output-file) OUTPUT_FILE="$2" ; shift ;;
    -n|--name) param_HasName="$2" ; shift ;;
    -w|--working-dir) param_HasWorkingDir="$2" ; shift ;;
    -a|--arguments) param_HasArguments="$2" ; shift ;;
    -i|--icon) param_HasIconLocation="$2" ; shift ;;
    --)        shift ; break ;;
    *)         echo "Option unknown : $1" ; exit 1 ;;
  esac
  shift
done

if [ $# -ne 0 ]; then
  echo "Option(s) unknown : $@"
  exit 1
fi

[ ${#LNK_TARGET} -eq 0 ] || [ ${#OUTPUT_FILE} -eq 0 ] && echo "
Usage :
${0} -l lnk_file_target [-n description] [-w working_dir] [-a cmd_args] [-i icon_path] -o my_file.lnk [-p]

Options:
  -l, --lnk-target      Specifies the target of the shortcut
  -o, --output-file     Save the shortcut to a file
  -n, --name            Specifies a description for the shortcut
  -w, --working-dir     Specifies the command starting directory
  -a, --arguments       Specifies the arguments of the launched command
  -i, --icon            Specify icon path
  -p, --printer-link    Generate a network printer-like shortcut
" && exit 1

#############################################################################################
# Functions
#############################################################################################

function ascii2hex() {
	echo $(echo -n ${1} | hexdump -v -e '/1 " x%02x"'|sed s/\ /\\\\/g)
}

function gen_LinkFlags() {
	echo '\x'$(printf '%02x' "$((HasLinkTargetIDList + HasName + HasWorkingDir + HasArguments + HasIconLocation))")${LinkFlags_2_3_4}
}

function gen_Data_string() {
        ITEM_SIZE=$(printf '%04x' $((${#1})))
        echo '\x'${ITEM_SIZE:2:2}'\x'${ITEM_SIZE:0:2}$(ascii2hex ${1})
}

function gen_IDLIST() {
        ITEM_SIZE=$(printf '%04x' $((${#1}/4+2)))
        echo '\x'${ITEM_SIZE:2:2}'\x'${ITEM_SIZE:0:2}${1}
}

function convert_CLSID_to_DATA() {
	echo -n ${1:6:2}${1:4:2}${1:2:2}${1:0:2}${1:11:2}${1:9:2}${1:16:2}${1:14:2}${1:19:4}${1:24:12}|sed s/"\([A-Fa-f0-9][A-Fa-f0-9]\)"/\\\\x\\1/g
}

#############################################################################################
# Variables from official Microsoft documentation
#############################################################################################

HasLinkTargetIDList=0x01
HasName=0x04
HasWorkingDir=0x10
HasArguments=0x20
HasIconLocation=0x40

HeaderSize='\x4c\x00\x00\x00'							# HeaderSize
LinkCLSID=$(convert_CLSID_to_DATA "00021401-0000-0000-c000-000000000046")	# LinkCLSID
LinkFlags_2_3_4='\x01\x00\x00'							# ForceNoLinkInfo
LinkFlags=""

FileAttributes_Directory='\x10\x00\x00\x00'					# FILE_ATTRIBUTE_DIRECTORY
FileAttributes_File='\x20\x00\x00\x00'						# FILE_ATTRIBUTE_ARCHIVE

CreationTime='\x00\x00\x00\x00\x00\x00\x00\x00'
AccessTime='\x00\x00\x00\x00\x00\x00\x00\x00'
WriteTime='\x00\x00\x00\x00\x00\x00\x00\x00'

FileSize='\x00\x00\x00\x00'
IconIndex='\x00\x00\x00\x00'
ShowCommand='\x01\x00\x00\x00'							# SW_SHOWNORMAL
Hotkey='\x00\x00'								# No Hotkey
Reserved='\x00\x00'								# Value cannot be modified
Reserved2='\x00\x00\x00\x00'							# Value cannot be modified
Reserved3='\x00\x00\x00\x00'							# Value cannot be modified
TerminalID='\x00\x00'								# Value cannot be modified

CLSID_Computer="20d04fe0-3aea-1069-a2d8-08002b30309d"				# My Computer
CLSID_Network="208d2c60-3aea-1069-a2d7-08002b30309d"				# Network Favorites

#############################################################################################
# Constants found from lnk file analysis
#############################################################################################

PREFIX_LOCAL_ROOT='\x2f'							# Local Disc
PREFIX_FOLDER='\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'		# File Folder
PREFIX_FILE='\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'			# File
PREFIX_NETWORK_ROOT='\xc3\x01\x81'						# Network file server root
PREFIX_NETWORK_PRINTER='\xc3\x02\xc1'						# Network printer

END_OF_STRING='\x00'

#############################################################################################

if [ ! -z "${param_HasName}" ]; then
	STRING_DATA=${STRING_DATA}$(gen_Data_string ${param_HasName})
else
	HasName=0x00
fi
if [ ! -z "${param_HasWorkingDir}" ]; then
	STRING_DATA=${STRING_DATA}$(gen_Data_string ${param_HasWorkingDir})
else
	HasWorkingDir=0x00
fi
if [ ! -z "${param_HasArguments}" ]; then
	STRING_DATA=${STRING_DATA}$(gen_Data_string ${param_HasArguments})
else
	HasArguments=0x00
fi
if [ ! -z "${param_HasIconLocation}" ]; then
	STRING_DATA=${STRING_DATA}$(gen_Data_string ${param_HasIconLocation})
else
	HasIconLocation=0x00
fi

LinkFlags=$(gen_LinkFlags)

# We remove the trailing backslash if there is one
LNK_TARGET=${LNK_TARGET%\\}

# We separate the root path from the link of the final target
# We also distinguish whether the link is local or network type
# We define the Item_Data value according to the case of a network or local link

IS_ROOT_LNK=0
IS_NETWORK_LNK=0

if [[ ${LNK_TARGET} == \\\\* ]]; then
	IS_NETWORK_LNK=1
	PREFIX_ROOT=${PREFIX_NETWORK_ROOT}
	Item_Data='\x1f\x58'$(convert_CLSID_to_DATA ${CLSID_Network})

        TARGET_ROOT=${LNK_TARGET%\\*}
        if [[ ${LNK_TARGET} == \\\\*\\* ]]; then
                TARGET_LEAF=${LNK_TARGET##*\\}
        fi
        if [ ${TARGET_ROOT} == \\ ]; then
                TARGET_ROOT=${LNK_TARGET}
        fi
else
	PREFIX_ROOT=${PREFIX_LOCAL_ROOT}
	Item_Data='\x1f\x50'$(convert_CLSID_to_DATA ${CLSID_Computer})

	TARGET_ROOT=${LNK_TARGET%%\\*}
        if [[ ${LNK_TARGET} == *\\* ]]; then
		TARGET_LEAF=${LNK_TARGET#*\\}
        fi
	[[ ! ${TARGET_ROOT} == *\\ ]] && TARGET_ROOT=${TARGET_ROOT}'\'
fi

if [ ${IS_PRINTER_LNK} -eq 1 ]; then
	PREFIX_ROOT=${PREFIX_NETWORK_PRINTER}
	TARGET_ROOT=${LNK_TARGET}
	IS_ROOT_LNK=1
fi

[ ${#TARGET_LEAF} -eq 0 ] && IS_ROOT_LNK=1

#############################################################################################

# We select the prefix that will be used to display the shortcut icon

if [[ ${TARGET_LEAF} == *.??? ]]; then
	PREFIX_OF_TARGET=${PREFIX_FILE}
	TYPE_TARGET="fichier"
	FileAttributes=${FileAttributes_File}
else
	PREFIX_OF_TARGET=${PREFIX_FOLDER}
	TYPE_TARGET="dossier"
	FileAttributes=${FileAttributes_Directory}
fi

# Convert target values to binary
TARGET_ROOT=$(ascii2hex "${TARGET_ROOT}")
TARGET_ROOT=${TARGET_ROOT}$(for i in `seq 1 21`;do echo -n '\x00';done) # Necessary from Vista and higher otherwise the link is considered empty (I couldn't find any information about this anywhere)

TARGET_LEAF=$(ascii2hex "${TARGET_LEAF}")

# We create the IDLIST which represents the heart of the LNK file

if [ ${IS_ROOT_LNK} -eq 1 ];then
	IDLIST_ITEMS=$(gen_IDLIST ${Item_Data})$(gen_IDLIST ${PREFIX_ROOT}${TARGET_ROOT}${END_OF_STRING})
else
	IDLIST_ITEMS=$(gen_IDLIST ${Item_Data})$(gen_IDLIST ${PREFIX_ROOT}${TARGET_ROOT}${END_OF_STRING})$(gen_IDLIST ${PREFIX_OF_TARGET}${TARGET_LEAF}${END_OF_STRING})
fi

IDLIST=$(gen_IDLIST ${IDLIST_ITEMS})

#############################################################################################

if [ ${IS_NETWORK_LNK} -eq 1 ]; then
	TYPE_LNK="réseau"
	if [ ${IS_PRINTER_LNK} -eq 1 ]; then
		TYPE_TARGET="imprimante"
	fi
else
	TYPE_LNK="local"
fi

echo "Creating shortcut of type \""${TYPE_TARGET}" "${TYPE_LNK}"\" with target "${LNK_TARGET} ${param_HasArguments} 1>&2

echo -ne ${HeaderSize}${LinkCLSID}${LinkFlags}${FileAttributes}${CreationTime}${AccessTime}${WriteTime}${FileSize}${IconIndex}${ShowCommand}${Hotkey}${Reserved}${Reserved2}${Reserved3}${IDLIST}${TerminalID}${STRING_DATA} > "${OUTPUT_FILE}"

