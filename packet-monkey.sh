#!/bin/bash
# $Revision$
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
# (c) Tim Brown, 2021
# <mailto:timb@nth-dimension.org.uk>
# <http://www.nth-dimension.org.uk/> / <http://www.machine.org.uk/>

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
