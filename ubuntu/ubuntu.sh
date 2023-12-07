#!/bin/bash

echo "  _   _  _____  _____  _____             _    _ _____ _____ _______ 	"
echo " | \ | |/ ____|/ ____|/ ____|       /\  | |  | |  __ \_   _|__   __|	"
echo " |  \| | |    | (___ | |           /  \ | |  | | |  | || |    | |   	"
echo ' | . ` | |     \___ \| |          / /\ \| |  | | |  | || |    | |   	'
echo " | |\  | |____ ____) | |____     / ____ \ |__| | |__| || |_   | |   	"
echo " |_| \_|\_____|_____/ \_____|   /_/    \_\____/|_____/_____|  |_|	  	"


echo ""
echo "###############################################################"
echo " Ensure /tmp is configured "
echo "###############################################################"
echo ""

findmnt -n /tmp
echo "---------------------------------------------------------------"
grep -E '\s/tmp\s' /etc/fstab | grep -E -v '^\s*#'
echo "---------------------------------------------------------------"
systemctl show "tmp.mount" | grep -i unitfilestate

echo ""
echo "###############################################################"
echo " Ensure /dev/shm is configured "
echo "###############################################################"
echo ""

findmnt -n /dev/shm
echo "---------------------------------------------------------------"
grep -E '\s/dev/shm\s' /etc/fstab

echo ""
echo "###############################################################"
echo " Ensure separate partition exists for /var "
echo "###############################################################"
echo ""

findmnt /var

echo ""
echo "###############################################################"
echo " Ensure separate partition exists for /var/tmp "
echo "###############################################################"
echo ""

findmnt /var/tmp

echo ""
echo "###############################################################"
echo " Ensure separate partition exists for /var/log "
echo "###############################################################"
echo ""

findmnt /var/log


echo ""
echo "###############################################################"
echo " Ensure separate partition exists for /home "
echo "###############################################################"
echo ""

findmnt /home

echo ""
echo "###############################################################"
echo " Ensure noexec option set on /tmp partition "
echo "###############################################################"
echo ""

findmnt -n /tmp | grep -Ev '\bnodev\b'
echo "Note: Nothing returned is passed "


echo ""
echo "###############################################################"
echo " Ensure nosuid option set on /tmp partition "
echo "###############################################################"
echo ""

findmnt -n /tmp -n | grep -Ev '\bnosuid\b'
echo "Note: Nothing returned is passed "

echo ""
echo "###############################################################"
echo " Ensure noexec option set on /dev/shm partition "
echo "###############################################################"
echo ""

findmnt -n /dev/shm | grep -Ev '\bnoexec\b'
echo "Note: Nothing returned is passed "

echo ""
echo "###############################################################"
echo " Ensure nosuid option set on /dev/shm partition "
echo "###############################################################"
echo ""

findmnt -n /dev/shm | grep -Ev '\bnosuid\b'
echo "Note: Nothing returned is passed "

echo ""
echo "###############################################################"
echo " Ensure /var/tmp partition includes the noexec option "
echo "###############################################################"
echo ""

findmnt -n /var/tmp | grep -Ev '\bnoexec\b'
echo "Note: Nothing returned is passed "


echo ""
echo "###############################################################"
echo " Ensure /var/tmp partition includes the nosuid option "
echo "###############################################################"
echo ""

findmnt -n /var/tmp | grep -Ev '\bnosuid\b'
echo "Note: Nothing returned is passed "


echo ""
echo "###############################################################"
echo " Ensure sticky bit is set on all world-writable directories "
echo "###############################################################"
echo ""

df --local -P 2> /dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
echo " Note: No output should be returned "

echo ""
echo "###############################################################"
echo " Disable Automounting "
echo "###############################################################"
echo ""

systemctl is-enabled autofs 
echo "---------------------------------------------------------------"
dpkg -s autofs


echo ""
echo "###############################################################"
echo " Disable USB Storage "
echo "###############################################################"
echo ""

modprobe -n -v usb-storage
echo "Note: install /bin/true"
echo "---------------------------------------------------------------"
lsmod | grep usb-storage
echo " Note: No output should be returned "

echo ""
echo "###############################################################"
echo " Ensure package manager repositories are configured "
echo "###############################################################"
echo ""

apt-cache policy

echo ""
echo "###############################################################"
echo " Ensure GPG keys are configured "
echo "###############################################################"
echo ""

apt-key list

echo ""
echo "###############################################################"
echo " Ensure permissions on bootloader config are configured "
echo "###############################################################"
echo ""

stat /boot/grub/grub.cfg
echo "Note: Access: (0400/-r--------) Uid: ( 0/ root) Gid: ( 0/ root)"

echo ""
echo "###############################################################"
echo " Ensure bootloader password is set "
echo "###############################################################"
echo ""

grep "^set superusers" /boot/grub/grub.cfg
echo "Note: set superusers="
grep "^password" /boot/grub/grub.cfg
echo "Note: password_pbkdf2 <username> <encrypted-password>"

echo ""
echo "###############################################################"
echo " Ensure authentication required for single user mode "
echo "###############################################################"
echo ""

grep -Eq '^root:\$[0-9]' /etc/shadow || echo "root is locked"
echo "Note: No results should be returned"


echo ""
echo "###############################################################"
echo " Ensure AppArmor is installed "
echo "###############################################################"
echo ""

dpkg -s apparmor | grep -E '(Status:|not installed)'
echo "Note: Status: install ok installed"

echo ""
echo "###############################################################"
echo " Ensure AppArmor is enabled in the bootloader configuration "
echo "###############################################################"
echo ""

grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1"
echo "---------------------------------------------------------------"
grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor"
echo "Note: Nothing should be returned"

echo ""
echo "###############################################################"
echo " Ensure all AppArmor Profiles are in enforce or complain mode"
echo "###############################################################"
echo ""

apparmor_status | grep profiles
echo "---------------------------------------------------------------"
apparmor_status | grep processes
echo "Note: review profile is loaded and verify no processes are unconfined"


echo ""
echo "###############################################################"
echo " Ensure time synchronization is in use "
echo "###############################################################"
echo ""

dpkg -s chrony
echo "---------------------------------------------------------------"
dpkg -s ntp

echo ""
echo "###############################################################"
echo " Ensure ntp is configured "
echo "###############################################################"
echo ""

systemctl is-enabled systemd-timesyncd
echo "---------------------------------------------------------------"
dpkg -s chrony | grep -E '(Status:|not installed)'
echo "---------------------------------------------------------------"
grep "^restrict" /etc/ntp.conf
echo "---------------------------------------------------------------"
grep -E "^(server|pool)" /etc/ntp.conf
echo "---------------------------------------------------------------"
grep "RUNASUSER=ntp" /etc/init.d/ntp


echo ""
echo "###############################################################"
echo " Ensure IP forwarding is disabled "
echo "###############################################################"
echo ""

sysctl net.ipv4.ip_forward
echo "Note: net.ipv4.ip_forward = 0"
echo "---------------------------------------------------------------"
grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
echo "No value should be returned"

echo ""
echo "###############################################################"
echo " Disable IPv6 "
echo "###############################################################"
echo ""

grep "^\s*linux" /boot/grub/grub.cfg | grep -v "ipv6.disable=1"
echo "Note: no lines should be returned"

echo ""
echo "###############################################################"
echo " Ensure TCP SYN Cookies is enabled "
echo "###############################################################"
echo ""

sysctl net.ipv4.tcp_syncookies
echo "Note: net.ipv4.tcp_syncookies = 1"
echo "---------------------------------------------------------------"
grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*
echo "Note: net.ipv4.tcp_syncookies = 1"

echo ""
echo "###############################################################"
echo " Ensure iptables(or nftables) is installed "
echo "###############################################################"
echo ""

apt list iptables iptables-persistent
echo "---------------------------------------------------------------"
dpkg-query -s nftables | grep 'Status: install ok installed'

echo ""
echo "###############################################################"
echo " Ensure iptables(or nftables) default deny firewall policy "
echo "###############################################################"
echo ""

iptables -L
echo "---------------------------------------------------------------"
nft list ruleset | grep 'hook input'
echo "---------------------------------------------------------------"
nft list ruleset | grep 'hook forward'
echo "---------------------------------------------------------------"
nft list ruleset | grep 'hook output'

echo ""
echo "###############################################################"
echo " Ensure iptables(or nftables) is enabled and running "
echo "###############################################################"
echo ""

systemctl is-enabled iptables
echo "---------------------------------------------------------------"
systemctl is-enabled nftables

echo ""
echo "###############################################################"
echo " Ensure iptables(or nftables) rules are saved "
echo "###############################################################"
echo ""

cat /etc/sysconfig/iptables

echo ""
echo "###############################################################"
echo " Ensure auditd is installed "
echo "###############################################################"
echo ""

dpkg -s auditd audispd-plugins

echo ""
echo "###############################################################"
echo " Ensure auditd service is enabled and running "
echo "###############################################################"
echo ""

systemctl is-enabled auditd
echo "---------------------------------------------------------------"
systemctl status auditd | grep 'Active: active (running) '

echo ""
echo "###############################################################"
echo " Ensure auditing for processes that start prior to auditd is enabled "
echo "###############################################################"
echo ""

grep "^\s*linux" /boot/grub/grub.cfg | grep -v "audit=1"
echo "Note: Nothing should be returned"

echo ""
echo "###############################################################"
echo " Ensure audit log storage size is configured "
echo "###############################################################"
echo ""

grep max_log_file /etc/audit/auditd.conf

echo ""
echo "###############################################################"
echo " Ensure audit logs are not automatically deleted "
echo "###############################################################"
echo ""

grep max_log_file_action /etc/audit/auditd.conf

echo ""
echo "###############################################################"
echo " Ensure system is disabled when audit logs are full "
echo "###############################################################"
echo ""

grep space_left_action /etc/audit/auditd.conf
echo "---------------------------------------------------------------"
grep action_mail_acct /etc/audit/auditd.conf
echo "---------------------------------------------------------------"
grep admin_space_left_action /etc/audit/auditd.conf


echo ""
echo "###############################################################"
echo "                   check config syslog server				     "
echo "###############################################################"
echo ""
cat /etc/rsyslog.conf

echo ""
echo "###############################################################"
echo " Ensure cron daemon is enabled and running "
echo "###############################################################"
echo ""

systemctl is-enabled crond
echo "---------------------------------------------------------------"
systemctl status cron | grep 'Active: active (running) '

echo ""
echo "###############################################################"
echo " Ensure permissions on /etc/crontab are configured "
echo "###############################################################"
echo ""

stat /etc/crontab
echo "Note: Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)"

echo ""
echo "###############################################################"
echo " Ensure cron is restricted to authorized users "
echo "###############################################################"
echo ""

stat /etc/cron.deny
echo "Note: stat: cannot stat /etc/cron.deny : No such file or directory"
echo "---------------------------------------------------------------"
stat /etc/cron.allow
echo "Note: Access: (0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 0/ root)"

echo ""
echo "###############################################################"
echo " Ensure sudo is installed "
echo "###############################################################"
echo ""

dpkg -s sudo
echo "---------------------------------------------------------------"
dpkg -s sudo-ldap

echo ""
echo "###############################################################"
echo " Ensure sudo commands use pty "
echo "###############################################################"
echo ""

grep -Ei '^\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$' /etc/sudoers /etc/sudoers.d/*
echo "Note: Defaults use_pty la pass"

echo ""
echo "###############################################################"
echo " Ensure sudo log file exists "
echo "###############################################################"
echo ""

grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/*
echo "Note: Defaults logfile= /var/log/sudo.log is pass"

echo ""
echo "###############################################################"
echo " Ensure permissions on /etc/ssh/sshd_config are configured "
echo "###############################################################"
echo ""

stat /etc/ssh/sshd_config

echo ""
echo "###############################################################"
echo " Ensure permissions on SSH private host key files are configured "
echo "###############################################################"
echo ""

find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;

echo ""
echo "###############################################################"
echo " Ensure permissions on SSH public host key files are configured "
echo "###############################################################"
echo ""

find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;

echo ""
echo "###############################################################"
echo " Ensure SSH access is limited "
echo "###############################################################"
echo ""

sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$'
echo "---------------------------------------------------------------"
grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' /etc/ssh/sshd_config

echo ""
echo "###############################################################"
echo " Ensure SSH root login is disabled "
echo "###############################################################"
echo ""

sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitrootlogin

echo ""
echo "###############################################################"
echo "                   check SSH config server				     "
echo "###############################################################"
echo ""
cat /etc/ssh/sshd_config 

echo ""
echo "###############################################################"
echo " Ensure password creation requirements are configured "
echo "###############################################################"
echo ""

grep '^\s*minlen\s*' /etc/security/pwquality.conf
echo "---------------------------------------------------------------"
grep '^\s*minclass\s*' /etc/security/pwquality.conf

echo ""
echo "###############################################################"
echo " Ensure lockout for failed password attempts is configured "
echo "###############################################################"
echo ""

grep "pam_tally2" /etc/pam.d/common-auth
echo "---------------------------------------------------------------"
grep -E "pam_(tally2|deny)\.so" /etc/pam.d/common-account

echo ""
echo "###############################################################"
echo " Ensure password hashing algorithm is SHA-512 "
echo "###############################################################"
echo ""

grep -E '^\s*password\s+(\[success=1\s+default=ignore\]|required)\s+pam_unix\.so\s+([^#]+\s+)?sha512\b' /etc/pam.d/common-password

echo ""
echo "###############################################################"
echo " Ensure password reuse is limited "
echo "###############################################################"
echo ""

grep -E '^\s*password\s+required\s+pam_pwhistory\.so\s+([^#]+\s+)?remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/common-password

echo ""
echo "###############################################################"
echo " Ensure accounts in /etc/passwd use shadowed passwords "
echo "###############################################################"
echo ""

awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}' /etc/passwd
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Ensure /etc/shadow password fields are not empty "
echo "###############################################################"
echo ""

awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Ensure all groups in /etc/passwd exist in /etc/group "
echo "###############################################################"
echo ""

for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
	grep -q -P "^.*?:[^:]*:$i:" /etc/group
	if [ $? -ne 0 ]; then
		echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
	fi
done
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Ensure shadow group is empty "
echo "###############################################################"
echo ""

grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
echo "---------------------------------------------------------------"
awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print}' /etc/passwd
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Ensure root is the only UID 0 account "
echo "###############################################################"
echo ""

awk -F: '($3 == 0) { print $1 }' /etc/passwd

echo ""
echo "###############################################################"
echo " Ensure root PATH Integrity "
echo "###############################################################"
echo ""

RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
echo "$RPCV" | grep -q "::" && echo "root's path contains a empty directory (::)"
echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
for x in $(echo "$RPCV" | tr ":" " "); do
	if [ -d "$x" ]; then
		ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working directory (.)"}
		$3 != "root" {print $9, "is not owned by root"}
		substr($1,6,1) != "-" {print $9, "is group writable"}
		substr($1,9,1) != "-" {print $9, "is world writable"}'
	else
		echo "$x is not a directory"
	fi
done
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Ensure all users' home directories exist "
echo "###############################################################"
echo ""

awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
	if [ ! -d "$dir" ]; then
		echo "User: \"$user\" home directory: \"$dir\" does not exist."
	fi
done
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Ensure users own their home directories "
echo "###############################################################"
echo ""

awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
	if [ ! -d "$dir" ]; then
		echo "User: \"$user\" home directory: \"$dir\" does not exist."
	else
		owner=$(stat -L -c "%U" "$dir")
		if [ "$owner" != "$user" ]; then
			echo "User: \"$user\" home directory: \"$dir\" is owned by \"$owner\""
		fi
	fi
done
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Ensure users' home directories permissions are 750 or more restrictive "
echo "###############################################################"
echo ""

awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $1 " " $6}' /etc/passwd | while read -r user dir; do
	if [ ! -d "$dir" ]; then
		echo "User: \"$user\" home directory: \"$dir\" doesn't exist"
	else
		dirperm=$(stat -L -c "%A" "$dir")
		if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo "$dirperm" | cut -c10)" != "-" ]; then
			echo "User: \"$user\" home directory: \"$dir\" has permissions:\"$(stat -L -c "%a" "$dir")\""
		fi
	fi
done
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Ensure users' dot files are not group or world writable "
echo "###############################################################"
echo ""

awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
	if [ -d "$dir" ]; then
		for file in "$dir"/.*; do
			if [ ! -h "$file" ] && [ -f "$file" ]; then
				fileperm=$(stat -L -c "%A" "$file")
				if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then
					echo "User: \"$user\" file: \"$file\" has permissions:\"$fileperm\""
				fi
			fi
		done
	fi
done
echo "Note: Nothing returned is passed"


echo ""
echo "###############################################################"
echo " Ensure no users have .netrc files "
echo "###############################################################"
echo ""

awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
	if [ -d "$dir" ]; then
		file="$dir/.netrc"
		if [ ! -h "$file" ] && [ -f "$file" ]; then
			if stat -L -c "%A" "$file" | cut -c4-10 | grep -Eq '[^-]+'; then
				echo "FAILED: User: \"$user\" file: \"$file\" exists with permissions: \"$(stat -L -c "%a" "$file")\", remove file or excessive permissions"
			else
				echo "WARNING: User: \"$user\" file: \"$file\" exists with permissions: \"$(stat -L -c "%a" "$file")\", remove file unless required"
			fi
		fi
	fi
done
echo "Note: FAILED: for any .netrc file with permissions less restrictive than 600"
echo "Note: WARNING: for any .netrc files that exist in interactive users' home directories."

echo ""
echo "###############################################################"
echo " Ensure no users have .rhosts files "
echo "###############################################################"
echo ""

awk -F: '($1!~/(root|halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
	if [ -d "$dir" ]; then
		file="$dir/.rhosts"
		if [ ! -h "$file" ] && [ -f "$file" ]; then
			echo "User: \"$user\" file: \"$file\" exists"
		fi
	fi
done
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Ensure password expiration is 365 days or less "
echo "###############################################################"
echo ""

grep ^\s*PASS_MAX_DAYS /etc/login.defs

echo ""
echo "###############################################################"
echo " Ensure system accounts are secured "
echo "###############################################################"
echo ""

awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd
awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' |
awk '($2!="L" && $2!="LK") {print $1}'
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Ensure default group for the root account is GID 0 "
echo "###############################################################"
echo ""

grep "^root:" /etc/passwd | cut -f4 -d:

echo ""
echo "###############################################################"
echo " Ensure default user umask is configured "
echo "###############################################################"
echo ""

passing=""
grep -Eiq '^\s*UMASK\s+(0[0-7][2-7]7|[0-7][2-7]7)\b' /etc/login.defs && grep -Eqi '^\s*USERGROUPS_ENAB\s*"?no"?\b' /etc/login.defs && grep -Eq '^\s*session\s+(optional|requisite|required)\s+pam_umask\.so\b' /etc/pam.d/common-session && passing=true
grep -REiq '^\s*UMASK\s+\s*(0[0-7][2-7]7|[0-7][2-7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\b' /etc/profile* /etc/bashrc* && passing=true
[ "$passing" = true ] && echo "Default user umask is set"
echo "----------------------------------------------------------------"
grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bash.bashrc*


echo ""
echo "###############################################################"
echo " Ensure default user shell timeout is configured "
echo "###############################################################"
echo ""

output1="" output2=""
[ -f /etc/bashrc ] && BRC="/etc/bashrc"
for f in "$BRC" /etc/profile /etc/profile.d/*.sh ; do
	grep -Pq '^\s*([^#]+\s+)?TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' "$f" && grep -Pq '^\s*([^#]+;\s*)?readonly\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && grep -Pq '^\s*([^#]+;\s*)?export\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && output1="$f"
done
grep -Pq '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh "$BRC" && output2=$(grep -Ps '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh $BRC)
if [ -n "$output1" ] && [ -z "$output2" ]; then
	echo -e "\nPASSED\n\nTMOUT is configured in: \"$output1\"\n"
else
	[ -z "$output1" ] && echo -e "\nFAILED\n\nTMOUT is not configured\n"
	[ -n "$output2" ] && echo -e "\nFAILED\n\nTMOUT is incorrectly configured in: \"$output2\"\n"
fi

echo ""
echo "###############################################################"
echo " Ensure root login is restricted to system console "
echo "###############################################################"
echo ""

cat /etc/securetty

echo ""
echo "###############################################################"
echo " Ensure permissions on /etc/passwd are configured "
echo "###############################################################"
echo ""

stat /etc/passwd

echo ""
echo "###############################################################"
echo " Ensure permissions on /etc/shadow are configured "
echo "###############################################################"
echo ""

stat /etc/shadow

echo ""
echo "###############################################################"
echo " Ensure permissions on /etc/gshadow are configured "
echo "###############################################################"
echo ""

stat /etc/gshadow

echo ""
echo "###############################################################"
echo " Ensure permissions on /etc/group are configured "
echo "###############################################################"
echo ""

stat /etc/group

echo ""
echo "###############################################################"
echo " Ensure no world writable files exist "
echo "###############################################################"
echo ""

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
echo "Note: Nothing returned is passed"

echo ""
echo "###############################################################"
echo " Audit SUID executables "
echo "###############################################################"
echo ""

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000

echo ""
echo "###############################################################"
echo " Audit SGID executables "
echo "###############################################################"
echo ""

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000
