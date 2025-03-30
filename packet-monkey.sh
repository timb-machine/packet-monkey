#!/bin/bash
# Copyright (c) 2021-2025, Tim Brown
# Copyright (c) 2021-2025, Cisco International Ltd
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the Cisco International Ltd nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL CISCO INTERNATIONAL LTD BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

. lib/misc/stdio

header () {
	printf "                  _        _                              _              \n"
	printf " _ __   __ _  ___| | _____| |_      _ __ ___   ___  _ __ | | _____ _   _ \n"
	printf "| '_ \ / _\` |/ __| |/ / _ \ __|____| '_ \` _ \ / _ \| '_ \| |/ / _ \ | | |\n"
	printf "| |_) | (_| | (__|   <  __/ ||_____| | | | | | (_) | | | |   <  __/ |_| |\n"
	printf "| .__/ \__,_|\___|_|\_\___|\__|    |_| |_| |_|\___/|_| |_|_|\_\___|\__, |\n"
	printf "|_|                                                                |___/ \n"
	printf "\n"
	printf "                                                      =[ @timb_machine ]=\n"
	printf "\n"
}

version () {
	header
	preamble
	printf "Brought to you by:\n"
	printf "\n"
	cat doc/AUTHORS
	exit 1
}

preamble () {
	printf "Shell script to analyse PCAPs using Wireshark filters.\n\n"
}

usage () {
	header
	preamble
	printf "Usage: %s\n" "${0}"
	printf "\n"
	printf "\t--help\tdisplay this help and exit\n"
	printf "\t--version\tdisplay version and exit\n"
	printf "\t--color\tenable output coloring\n"
	printf "\t--verbose\tverbose level (0-2, default: 1)\n"
	printf "\t--type\tselect from one of the following filter types:\n"
	for filtertype in lib/filters/enabled/*
	do
		printf "\t\t%s\n" "$(basename "${filtertype}")"
	done
	printf "\t--filters\tprovide a comma separated list of filters to run, select from the following filters:\n"
	for filter in lib/filters/*
	do
		if [ "$(basename "${filter}")" != "enabled" ]
		then
			printf "\t\t%s\n" "$(basename "${filter}")"
		fi
	done
	printf "\t--streams\tdump full streams\n"
	printf "\t--pcapfilename\tprovide a PCAP to process\n"
	exit 1
}

# TODO make it use lib/misc/validate
COLORING="0"
VERBOSE="1"
TYPE="all"
FILTERS=""
STREAMS="0"
PCAPFILENAME=""
while [ -n "${1}" ]
do
	case "${1}" in
		--help|-h)
			usage
			;;
		--version|-v|-V)
			version
			;;
		--color)
			COLORING="1"
			;;
		--verbose)
			shift
			VERBOSE="${1}"
			;;
		--type|-t)
			shift
			TYPE="${1}"
			;;
		--filters|-f)
			shift
			FILTERS="${1}"
			;;
		--streams|-s)
			STREAMS="1"
			;;
		--pcapfilename|-p)
			shift
			PCAPFILENAME="${1}"
	esac
	shift
done
header
if [ "${VERBOSE}" != "0" -a "${VERBOSE}" != "1" -a "${VERBOSE}" != "2" ]
then
	stdio_message_error "packet-monkey" "the provided verbose level ${VERBOSE} is invalid - use 0, 1 or 2 next time"
	VERBOSE="1"
fi
if [ ! -e "${PCAPFILENAME}" ]
then
	stdio_message_error "packet-monkey" "the provided pcap file '${PCAPFILENAME}' is invalid"
	exit 1
fi
if [ -n "${FILTERS}" ]
then
	for filterfilename in $(printf "${FILTERS}" | tr -d " " | tr "," " ")
	do
		if [ ! -e "lib/filters/${filterfilename}" ]
		then
			stdio_message_error "packet-monkey" "the provided filter name '${filterfilename}' does not exist"
		else
			filtername="$(basename "${filterfilename}")"
        		outputfilename="$(basename "${PCAPFILENAME}" | sed "s/.pcap//g")-${filtername}.pcap"
			filter="$(cat "lib/filters/${filterfilename}")"
			stdio_message_log "packet-monkey" "${filtername}: ${filter}"
			if [ "${STREAMS}" -eq 1 -a -n "$(printf "${filter}" | grep "tcp")" ]
			then
				stdio_message_log "packet-monkey" "${filtername}: mangling tcp sessions"
				stdio_message_debug "tshark" "$(tshark -r "${PCAPFILENAME}" -T fields -e tcp.srcport -2 -R "${filter}" | awk '{ printf(" %s tcp.port == %s", sep, $1); sep="||" }')"
				tshark -r "${PCAPFILENAME}" -w "${outputfilename}" -2 -R "$(tshark -r "${PCAPFILENAME}" -T fields -e tcp.srcport -2 -R "${filter}" | awk '{ printf("%s tcp.port == %s", sep, $1); sep="||" }')"
			else
				if [ "${STREAMS}" -eq 1 -a -n "$(printf "${filter}" | grep "udp")" ]
				then
					stdio_message_log "packet-monkey" "${filtername}: mangling udp sessions"
					tshark -r "${PCAPFILENAME}" -w "${outputfilename}" -2 -R "$(tshark -r "${PCAPFILENAME}" -T fields -e udp.srcport -2 -R "${filter}" | awk '{ printf(" %s udp.port == %s", sep, $1); sep="||" }')"
				else
					tshark -r "${PCAPFILENAME}" -w "${outputfilename}" -2 -R "${filter}"
				fi
			fi
			du -sh "${outputfilename}"
		fi
	done
else
	if [ ! -d "lib/filters/enabled/${TYPE}" ]
	then
		stdio_message_error "packet-monkey" "the provided filter type '${TYPE}' does not exist"
	else
		for filterfilename in lib/filters/enabled/${TYPE}/*
		do
			filtername="$(basename "${filterfilename}")"
			outputfilename="$(basename "${PCAPFILENAME}" | sed "s/.pcap//g")-${filtername}.pcap"
			filter="$(cat "${filterfilename}")"
			stdio_message_log "packet-monkey" "${filtername}: ${filter}"
			if [ "${STREAMS}" -eq 1 -a -n "$(printf "${filter}" | grep "tcp")" ]
			then
				stdio_message_log "packet-monkey" "${filtername}: mangling tcp sessions"
				tshark -r "${PCAPFILENAME}" -w "${outputfilename}" -2 -R "$(tshark -r "${PCAPFILENAME}" -T fields -e tcp.srcport -2 -R "${filter}" | awk '{ printf("%s tcp.port == %s", sep, $1); sep="||" }')"
			else
				if [ "${STREAMS}" -eq 1 -a -n "$(printf "${filter}" | grep "udp")" ]
				then
					stdio_message_log "packet-monkey" "${filtername}: mangling udp sessions"
					tshark -r "${PCAPFILENAME}" -w "${outputfilename}" -2 -R "$(tshark -r "${PCAPFILENAME}" -T fields -e udp.srcport -2 -R "${filter}" | awk '{ printf("%s udp.port == %s", sep, $1); sep="||" }')"
				else
					tshark -r "${PCAPFILENAME}" -w "${outputfilename}" -2 -R "${filter}"
				fi
			fi
			du -sh "${outputfilename}"
		done
	fi
fi
exit 0
