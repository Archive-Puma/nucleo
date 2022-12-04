#!/bin/sh

#  _________________________
# |     Print the banner    |
#  -------------------------
#     \   ^__^
#      \  (oo)\_______
#         (__)\       )\/\
#             ||----w |
#             ||     ||

cat << BANNER
                     __         
   ____  __  _______/ /__  ____ 
  / __ \\/ / / / ___/ / _ \\/ __ \\
 / / / / /_/ / /__/ /  __/ /_/ /
/_/ /_/\\__,_/\\___/_/\\___/\\____/  1.0.0

                         kike.wtf

BANNER

#          _\|/_
#          (o o)
#  +----oOO-{_}-OOo-+
#  |Colored outputs!|
#  +---------------*/

blu='\033[34m'
ylw='\033[33m'
grn='\033[32m'
red='\033[31m'
bld='\033[1m'
rst='\033[0m'

#  __________________
# /\                 \
# \_| Logger helpers |
#   |   _____________|_
#    \_/_______________/

# Messages
trc() {
    test "${verbose}" -gt 1 && echo "[TRC] $1"
}
dbg() {
    test "${verbose}" -gt 0 && echo "[${grn}DBG${rst}] ${1}"
}
inf() {
    echo "[${blu}MSG${rst}] ${1}"
}
wrn() {
    echo "[${ylw}WRN${rst}] ${1}"
}
err() {
    echo "[${red}ERR${rst}] ${1}"
}
halt() {
    err "${1}"
    exit 1
}

# Issues
issue() {
    if test -z "${reported}"; then
        case "${severity}" in
            3) risk="${red}HGH" ;;
            2) risk="${ylw}MED" ;;
            1) risk="${grn}LOW" ;;
            *) risk="${blu}INF" ;;
        esac
        echo "[${bld}${risk}${rst}][${category}][${ylw}${title}${rst}] ${1}"
        reported='true'
    fi
}

#  ___________________
# /                   \
# |  Argument parser  |
# \_____________  __'\
#               |/   \\
#                \    \\  .
#                     |\\/|
#                     / " '\
#                     . .   .
#                    /    ) |
#                   '  _.'  |
#                   '-'/    \

# Arguments
target=     # Target(s) to scan
tmout=2     # Time to run each test
verbose=0   # Verbosity

# Help function
help() {
cat << HELP
nucleo is a script that checks common vulnerabilities and security misconfigurations.

Usage:
  ${0} [flags]

Flags:
   -t, -target string   target host or path to file containing a list of target hosts to scan (one per line)

   -no-color            disable colored output
   -timeout integer     request timeout (in seconds)

   -h, -help            display this usage summary and exit
   -v, -verbose         increase the verbosity output level (max. 2)
HELP
exit
}

while :; do
    case "${1}" in
        -h|-help|--help)
            help
            ;;

        -no-color|--no-color)
            red=
            ylw=
            grn=
            blu=
            bld=
            rst=
            ;;

        -t|-target|--target)
            if test -n "${2}"; then
                target="${2}"
                shift
            else halt '--target requires a non-empty option argument'; fi
            ;;
        -t=?*|-target=?*|--target=?*)
            target="${1#*=}"
            ;;
        -t=|-target=|--target=)
            halt '--target requires a non-empty option argument'
            ;;

        -timeout|--timeout)
            if test -n "${2}"; then
                tmout="${2}"
                shift
            else halt '--timeout requires a non-empty option argument'; fi
            ;;
        -timeout=?*|--timeout=?*)
            tmout="${1#*=}"
            ;;
        -timeout=|--timeout=)
            halt '--timeout requires a non-empty option argument'
            ;;

        -vv)
            verbose=2
            ;;
        -v|-verbose|--verbose)
            verbose=$((verbose + 1))
            ;;

        *)
            break
    esac
    shift
done

#  _________________________
# | Responsability message! |
#  -------------------------
#     \
#        .--.
#       |o_o |
#       |:_/ |
#      //   \ \
#     (|     | )
#    /'\_   _/`\
#    \___)=(___/

wrn 'Use with caution. You are responsible for your actions.'
wrn 'Developers assume no liability and are not responsible for any misuse or damage.'

#  /\ !!!!!!!!!!!!!!!!!!!!!! /\
# |! |                      |! |
# |! | Pre-execution checks |! |
# |__|                      |__|
# (__)!!!!!!!!!!!!!!!!!!!!!!(__)

# Check the target
hosts="$(mktemp --suffix 'nucleo')"
if test -z "${target}"; then
    halt "No target(s) specified"
elif test -f "${target}"; then
    sed -e '/^$/d' -e '/^#/d' "${target}" | sort -u > "${hosts}"
else
    trc "Saving target inside ${hosts}"
    echo "${target}" > "${hosts}"
fi
inf "$(wc -l < "${hosts}") target(s) loaded."

# Check the timeout
test "${tmout}" -eq "${tmout}" 2>/dev/null || halt '--timeout requires a numeric argument'
trc "Timeout set to ${tmout} seconds"

#  /\ /\ /\ /\ /\ /\ /\ /\
# |__|__|__|__|__|__|__|__|
# |  |  |  |  |  |  |  |  |
# |  |  Issue checker  |  |
# |__|__|__|__|__|__|__|__|
# |__|__|__|__|__|__|__|__|

echo
while read -r host; do

# -------------------------
#  22/TCP -- SSH
# -------------------------
    category='ssh'
    ssh_algos="$(echo "SSH-2.0-Pumita" | timeout "${tmout}" nc -q 5 "${host}" 22 | tail -1 | strings -n 4 | uniq | grep -oE "[a-zA-Z0-9@.,-]+$")"

    test -n "${ssh_algos}" || continue

# ---- Password-Based Authentication Supported
    reported=
    severity=1
    title='password-based-authentication'

    methods="$(ssh -v -n -o Batchmode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "NOT_PUMITA@${host}" 2>&1 | awk '/Authentications/ {print $6}' | sort -u )"
    if echo "${methods}" | grep -q password; then
        issue "${host}"
        for method in $(echo "${methods}" | tr ',' '\n'); do
            dbg "|_ ${method}"
        done
    fi

# ---- RC4 Encryption Algorithm Enabled
    reported=
    severity=1
    title='rc4-algorithm'

    for algo in $(echo "${ssh_algos}" | sed '3!d;s/,/\n/g' | grep 'arcfour'); do
        issue "${host}"
        dbg "|_ ${algo}"
    done

# ---- Weak Encryption Algorithms Supported
    reported=
    severity=1
    title='weak-encryption-algorithm'

    for algo in $(echo "${ssh_algos}" | sed '3!d;s/,/\n/g' | grep -E '(arcfour|none|-cbc)'); do
        issue "${host}"
        dbg "|_ ${algo}"
    done

# ---- Weak Key Exchange Algorithms Supported
# https://www.virtuesecurity.com/kb/ssh-weak-key-exchange-algorithms-enabled/
    reported=
    severity=1
    title='weak-key-exchange-algorithm'

    for algo in $(echo "${ssh_algos}" | sed '1!d;s/,/\n/g' | grep -E '(rsa1024|sha1(-.+)?$)'); do
        issue "${host}"
        dbg "|_ ${algo}"
    done

# ---- Weak MAC Algorithms Supported
# https://www.virtuesecurity.com/kb/ssh-weak-mac-algorithms-enabled/
    reported=
    severity=0
    title='weak-mac-algorithm'

    for algo in $(echo "${ssh_algos}" | sed '4!d;s/,/\n/g'); do
        size="$(echo "${algo}" | grep -oE '\-[0-9]+' | tr -d '-')"
        if { test -n "${size}" && test "${size}" -lt 128; } || echo "${algo}" | grep -q 'md5'; then
            issue "${host}"
            dbg "|_ ${algo}"
        fi
    done


done < "${hosts}"

#          _ ._  _ , _ ._
#        (_ ' ( `  )_  .__)
#      ( (  (    )   `)  ) _)
#     (__ (_   (_ . _) _) ,__)
#         `~~`\ ' . /`~~`
#         ,::: ;   ; :::,
#        ':::::::::::::::'
#  ___________/_ __ \__________
# |                            |
# | Post-execution clean tasks |
# |____________________________|

test -n "${hosts}" && rm "${hosts}"
