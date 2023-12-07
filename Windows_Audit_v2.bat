@echo off

echo "  _   _  _____  _____  _____             _    _ _____ _____ _______ 	"
echo " | \ | |/ ____|/ ____|/ ____|       /\  | |  | |  __ \_   _|__   __|	"
echo " |  \| | |    | (___ | |           /  \ | |  | | |  | || |    | |   	"
echo " | . ` | |     \___ \| |          / /\ \| |  | | |  | || |    | |   	"
echo " | |\  | |____ ____) | |____     / ____ \ |__| | |__| || |_   | |   	"
echo " |_| \_|\_____|_____/ \_____|   /_/    \_\____/|_____/_____|  |_|	    "
echo:
echo:
echo I.Kiem tra cai dat ban va
echo [+] Kiem tra cai dat Service Pack
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra cai dat HotFix
wmic qfe get Caption,Description,HotFixID,InstalledOn | more
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra cai dat tu dong update
wuauclt.exe /detectnow
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra ket noi WSUS
REG QUERY "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo:
echo:
echo II. Danh gia chinh sach kiem toan
echo [+] Kiem tra chinh sach kiem toan tai khoan mat khau
net accounts
echo ###################################################################
echo ###################################################################
@echo:
@echo:



echo [+] Kiem tra chinh sach phan quyen tai khoan
echo #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
echo [-] Danh sach tai khoan
net user
echo #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
@echo:
@echo:

echo [-] Danh sach cac nhom nguoi dung
net localgroup
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra chinh sach tuong lua
netsh advfirewall show allprofiles state
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra chinh sach cau hinh Event Log
wevtutil gl System
echo #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
wevtutil gl Application
echo #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
wevtutil gl Security
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] List Audit policy
auditpol /get /category:*
echo ###################################################################
echo ###################################################################
@echo:
@echo:


echo:
echo:
echo: III.Kiem tra cau hinh thiet bi
echo [+] Kiem tra thong tin may tram
echo #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
echo [-] Thong tin phan cung
systeminfo
echo #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
echo [-] dong bo thoi gian
w32tm /query /status
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [-] Kiem tra license
cscript c:\Windows\System32\slmgr.vbs /dli
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+]Danh sach o share
net share
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra cac phan mem cai dat
wmic product get name,version
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra cac dich vu dang chay tren he thong
echo [+] Kiem tra Services list
net start
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra Tasklist
TASKLIST /svc
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra cac ket noi mang tren thiet bi
netstat -ab
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra User Rights Assignment
secedit /export /areas User_Rights_Assignment /cfg USER_RIGHTS.txt
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra Start up list
wmic startup get caption,command
echo #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>nul
echo #-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra Task Schedule
schtasks
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Tim kiem file chua du lieu nhay cam
cd %USERPROFILE% 2>nul && dir /s/b *password* == *credential* 2>nul
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Security Settings
secedit /export /cfg sec_settings.txt
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra cai dat AV
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get * /value
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] List Unquoted service Path
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\" |findstr /i /v """
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Writable Service Executables
for /f "tokens=2 delims='='" %%a in ('cmd.exe /c wmic service list full ^| findstr /i "pathname" ^|findstr /i /v "system32"') do (
    for /f eol^=^"^ delims^=^" %%b in ("%%a") do icacls "%%b" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos usuarios %username%" && ECHO.
)
echo ###################################################################
echo ###################################################################
@echo:
@echo:

echo [+] Kiem tra GPO tu may chu AD ap dung xuong may tram
gpresult /v
echo ###################################################################
echo ###################################################################
@echo:
@echo:



