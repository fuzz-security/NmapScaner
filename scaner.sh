#!/bin/bash

# 适用于对前期所搜集到的各种目标子域集中进行批量端口扫描及服务识别
# 为有效绕过对方的各种扫描防护监测,已对nmap的一些典型扫描特征进行了剔除,对每个目标域名同时只会扫一个端口,并以此轮询
# Tested on Ubuntu 16.04

if [ $# -eq 0 ] || [ $# != 1 ];then
    echo -e "\nUsage:\n"
    echo -e "    # nohup ./scaner.sh 端口列表文件  &"
    echo -e "    # tail -f nohup.out  &\n"
    exit
fi

target=$1

# 安装各类基础工具及相关依赖
apt-get update >/dev/null 2>&1
apt-get install git p7zip-full gcc make libpcap-dev clang openssl libssh2-1-dev build-essential build-essential libssl-dev libpq5 libpq-dev libssh2-1 libssh2-1-dev libgcrypt11-dev libgnutls-dev libsvn-dev freerdp-x11 libfreerdp-dev git libssl-dev libssh-dev libidn11-dev libpcre3-dev libgtk2.0-dev libmysqlclient-dev libpq-dev libsvn-dev firebird-dev libgcrypt11-dev libncurses5-dev -y >/dev/null 2>&1
if [ $? -eq 0 ];then
    echo -e "\n\e[94m所有基础工具及相关依赖已成功安装 ! \e[0m"
	sleep 2
else
    echo -e "安装错误,请仔细检查后重试! "
    exit
fi

# 安装nmap ( 把已经事先处理好的nmap[去除扫描特征]传到vps上 )
which "nmap" > /dev/null
if [ $? -eq 0 ];then
    echo -e "\e[94m当前系统已安装过 Nmap ! \e[0m"
	sleep 2
else
	7z x nmap-7.80.7z && cd nmap-7.80 && chmod +x ./* && ./configure >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
	if [ $? -eq 0 ];then
		echo -e "\e[94mNmap已成功安装 ! \e[0m"
		cd ..
		rm -fr nmap-7.80*
	else
		echo -e "Nmap安装失败 ! 请确认nmap-7.80.7z是否已事先放到脚本同目录下 ! "
		exit
	fi
fi

# 绕过检测但端口扫描
while read -r port
do
	# 如下基本已覆盖大部分常用Web端口
    if [ $port -ge 79 -a  $port -le 91 ] || [ $port -ge 8079 -a $port -le 8091 ] || [ $port -eq 443 ] || [ $port -eq 31999 ] || [ $port -eq 9443 ] || [ $port -eq 1158 ] || [ $port -eq 8443 ] || [ $port -eq 4443 ] || [ $port -ge 8001 -a $port -le 8010 ] || [ $port -eq 8100 ] || [ $port -eq 8333 ] || [ $port -eq 8222 ] || [ $port -eq 10000 ] || [ $port -eq 9999 ] ;then
	# 因为反解 + 加载脚本 会耗时很久,所以此处只加了选项和部分脚本
    nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=http-waf-detect.nse,http-vuln-cve2017-5638.nse,http-vuln-cve2017-1001000.nse,vmware-version.nse,ssl-heartbleed.nse,http-shellshock.nse,http-cisco-anyconnect.nse,http-headers.nse,http-title.nse,http-robots.txt.nse,http-iis-webdav-vuln.nse -oN ./Web_${port}.txt >/dev/null 2>&1
        
	# 信息搜集脚本
    # citrix-enum-servers-xml.nse,ssl-heartbleed.nse,http-shellshock.nse,http-cisco-anyconnect.nse,http-waf-detect.nse,http-waf-fingerprint.nse
    # http-axis2-dir-traversal.nse,http-backup-finder.nse,http-wordpress-users.nse,vmware-version.nse
    # http-methods.nse,http-webdav-scan.nse,http-iis-shortame-brute.nse,http-git.nse,jdwp-version.nse
        
	# 漏洞检测脚本 
	# tomcat-cve-2017-12615.nse,http-pulse_ssl_vpn.nse,CVE-2019-19781.nse,struts2-scan.nse,cisco-cve-2019-1937.nse,cve_2019_1653.nse
	# http-vuln-cve2017-8917.nse,http-vuln-cve2017-5638.nse,http-vuln-cve2017-1001000.nse
    fi

    # ELK常用端口
    if [ $port -ge 9200 -a $port -le 9300 ] ;then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script= -oN ./ELK_${port}.txt >/dev/null 2>&1
    fi
	
	# Weblogic常用端口
    if [ $port -ge 7001 -a $port -le 7010 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=weblogic-CNVD-C-2019-48814.nse -oN ./Weblogic.txt >/dev/null 2>&1
        # 相关漏洞探测脚本 , weblogic-cve-2018-2894.nse , weblogic-CNVD-C-2019-48814.nse
    fi

    # SSH 默认端口,弱口令字典需要事先自行精心准备(亦可用提供的字典生成脚本针对性生成),之后把nmap的默认字典全部替换掉即可,切记,量先不要太大,容易卡住
    if [ $port -eq 22 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./SSH.txt >/dev/null 2>&1
        # echo -e "\033[35m尝试爆破目标 Ssh,请耐心等待...\033[0m"
		# echo root > /usr/local/share/nmap/nselib/data/usernames.lst
		# echo admin >> /usr/local/share/nmap/nselib/data/usernames.lst
		# nmap -p 22 -iL $1 -Pn -sT -sV  -vv --open --script=ssh-brute.nse --script-args userdb=usernames.lst,passdb=passwords.lst --script-args ssh-brute.timeout=5s -oN ./SSH_login.txt >/dev/null 2>&1
        # echo -e "\033[35mSsh 爆破完毕 ! 结果已存到当前目录的SSH_login.txt文件中\033[0m"
    fi

	# Sangfor SSH 默认端口,爆破速度一般 [默认只扫描不启用爆破]
	if [ $port -eq 22345 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Sangfor_SSH.txt >/dev/null 2>&1
		# echo -e "\033[35m尝试爆破目标 Sangfor Ssh,请耐心等待...\033[0m"
		# echo admin > /usr/local/share/nmap/nselib/data/usernames.lst
		# echo root >> /usr/local/share/nmap/nselib/data/usernames.lst
		# nmap -p 22345 -iL $1 -Pn -sT -sV  -vv --open --script=ssh-brute.nse --script-args userdb=usernames.lst,passdb=passwords.lst --script-args ssh-brute.timeout=5s -oN ./Sangfor_SSH_login.txt >/dev/null 2>&1
		# echo -e "\033[35mSangforSsh 爆破完毕 ! 结果已存到当前目录的Sangfor_SSH_login.txt文件中\033[0m"
	fi

	# Sangfor VPN默认管理端口
	if [ $port -eq 4430 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./SangforVpn_admin.txt >/dev/null 2>&1
    fi

	# PPTP VPN默认连接端口
	if [ $port -eq 1723 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./PptpVpn.txt >/dev/null 2>&1
    fi

	# Svn默认端口
	if [ $port -eq 3690 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Svn.txt >/dev/null 2>&1
    fi

    # RDP默认端口
    if [ $port -eq 3389 ];then
        echo "Rdp Scaning ....."
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./RDP.txt >/dev/null 2>&1
        # 可选检测脚本 rdp-vuln-ms12-020.nse
    fi

    # Mssql默认端口,爆破速度还行
    if [ $port -eq 1433 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=ms-sql-empty-password.nse -oN ./Mssql.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 Mssql,请耐心等待...\033[0m"
		echo sa > /usr/local/share/nmap/nselib/data/usernames.lst
		nmap -p 1433 -iL $1 -Pn -sT -sV  -vv --open --script=ms-sql-empty-password.nse,ms-sql-brute.nse --script-args userdb=usernames.lst,passdb=passwords.lst --script-args ssh-brute.timeout=5s -oN ./Mssql_login.txt >/dev/null 2>&1
        echo -e "\033[35mMssql 爆破完毕 ! 结果已存到当前目录的Mssql_login.txt文件中\033[0m"
    fi

    # MySQL Login 爆破速度稍慢
    if [ $port -ge 3306 -a $port -le 3308 ] ;then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=mysql-empty-password.nse -oN ./MySQL.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 MySQL,请耐心等待...\033[0m"
		echo root > /usr/local/share/nmap/nselib/data/usernames.lst
		nmap -p 3306 -iL $1 -Pn -sT -sV  -vv --open --script=mysql-empty-password.nse,mysql-brute.nse --script-args ssh-brute.timeout=5s -oN ./MySQL_login.txt >/dev/null 2>&1
        echo -e "\033[35mMySQL 爆破完毕 ! 结果已存到当前目录的MySQL_login.txt文件中\033[0m"
    fi

    # Redis Login 爆破速度很快
    if [ $port -eq 6379 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=redis-info.nse -oN ./Redis.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 Redis,请耐心等待...\033[0m"
		nmap -p 6379 -iL $1 -Pn -sT -sV  -vv --open --script=redis-info.nse,redis-brute.nse --script-args ssh-brute.timeout=5s -oN ./Redis_login.txt >/dev/null 2>&1
        echo -e "\033[35mRedis 爆破完毕 ! 结果已存到当前目录的Redis_login.txt文件中\033[0m"
    fi

    # Postgresql Login 爆破速度很快
    if [ $port -eq 5432 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Postgresql.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 Postgresql,请耐心等待...\033[0m"
		echo postgres > /usr/local/share/nmap/nselib/data/usernames.lst
		nmap -p 5432 -iL $1 -Pn -sT -sV  -vv --open --script=pgsql-brute.nse --script-args ssh-brute.timeout=5s -oN ./Postgresql_login.txt >/dev/null 2>&1
        echo -e "\033[35mPostgresql 爆破完毕 ! 结果已存到当前目录的Postgresql_login.txt文件中\033[0m"
    fi

    # SMB Login 爆破基本不可用,漏扫可以,内网用
    if [ $port -eq 445 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Smb.txt >/dev/null 2>&1
        # echo -e "\033[35m尝试爆破目标 SMB,请耐心等待...\033[0m"
		# echo administrator > /usr/local/share/nmap/nselib/data/usernames.lst
		# nmap -p U:137,T:139,445 $1 -Pn -sT -sV  -vv --open --script=smb-brute.nse,smb-vuln-ms17-010.nse,smb-vuln-ms08-067.nse,smb-os-discovery.nse -oN ./Smb_login.txt >/dev/null 2>&1
        # echo -e "\033[35mSMB 爆破完毕 ! 结果已存到当前目录的Smb_login.txt文件中\033[0m"
    fi

    # Telnet默认端口
    if [ $port -eq 23 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Telnet.txt >/dev/null 2>&1
    fi

    # ldap默认端口,爆破基本不可用
    if [ $port -eq 389 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Ldap.txt >/dev/null 2>&1
    fi

    # Oracle默认端口,爆破基本不可用
    if [ $port -eq 1521 ];then
        # 可选检测脚本 oracle-sid-brute.nse
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Oracle.txt >/dev/null 2>&1
    fi

    # MongoDB默认端口,爆破速度一般(有漏报)
    if [ $port -eq 27017 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=mongodb-info.nse -oN ./MongoDB.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 MongoDB,请耐心等待...\033[0m"
		echo root > /usr/local/share/nmap/nselib/data/usernames.lst
		echo admin >> /usr/local/share/nmap/nselib/data/usernames.lst
		nmap -p 27017 -iL $1 -Pn -sT -sV  -vv --open --script=mongodb-brute.nse --script-args ssh-brute.timeout=5s -oN ./MongoDB_login.txt >/dev/null 2>&1
		echo -e "\033[35mMongoDB 爆破完毕 ! 结果已存到当前目录的MongoDB_login.txt文件中\033[0m"
	fi

	# Memcached 
	if [ $port -eq 11211 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=memcached-info.nse -oN ./Memcached.txt >/dev/null 2>&1
    fi

    # FTP
    if [ $port -eq 21 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=ftp-anon.nse,ftp-proftpd-backdoor.nse,ftp-vsftpd-backdoor.nse -oN Ftp.txt >/dev/null 2>&1
    fi

    # Rsync
    if [ $port -eq 873 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=rsync-list-modules.nse -oN ./Rsync.txt >/dev/null 2>&1
    fi

    # NFS
    if [ $port -eq 2049 ]  || [ $port -eq 111 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=nfs-showmount.nse -oN ./Nfs.txt >/dev/null 2>&1
    fi

    # POP3
    if [ $port -eq 110 ] || [ $port -eq 995 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Pop3.txt >/dev/null 2>&1
    fi

    # IMAP
    if [ $port -eq 143 ] || [ $port -eq 993 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Imap.txt >/dev/null 2>&1
    fi

    # SMTP
    if [ $port -eq 25 ]  || [ $port -eq 465 ] || [ $port -eq 587 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Smtp.txt >/dev/null 2>&1
        # 可选检测脚本 smtp-vuln-cve2019-15846.nse
    fi
	
	# Zimbra 默认管理控制台
    if [ $port -eq 7071 ] ;then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=http-headers.nse,http-title.nse -oN ./Zimbra.txt >/dev/null 2>&1
    fi
	
    # VNC
    if [ $port -eq 5900 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Vnc.txt >/dev/null 2>&1
    fi

    # DNS
    if [ $port -eq 53 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./DNS.txt >/dev/null 2>&1
    fi

    # CouchDB
    if [ $port -eq 5984 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./CouchDB.txt >/dev/null 2>&1
    fi

    # FortiOS SSLVPN
    if [ $port -eq 10443 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=http-vuln-cve2018-13379.nse -oN ./FortiVpn.txt >/dev/null 2>&1
        # 可选检测脚本 http-vuln-cve2018-13379.nse
    fi

    # ike-version
    if [ $port -eq 500 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Ike.txt >/dev/null 2>&1
        # 可选检测脚本 ike-version.nse
    fi

    # SOCKS
    if [ $port -eq 1080 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Socks.txt >/dev/null 2>&1
    fi

    # Nessus
    if [ $port -eq 1241 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./Nessus.txt >/dev/null 2>&1
    fi

	# JavaRmi
    if [ $port -eq 1099 ];then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open -oN ./JavaRmi.txt >/dev/null 2>&1
    fi

	# Vmware Exsi
    if [ $port -eq 902 ] ;then
        nmap -p $port -iL $1 -Pn -sT -sV  -vv --open --script=vmware-version.nse,vmauthd-brute.nse -oN ./Vmware_Exsi.txt >/dev/null 2>&1
        echo -e "\033[35m尝试爆破目标 Vmware Exsi,请耐心等待...\033[0m"
		echo root > /usr/local/share/nmap/nselib/data/usernames.lst
		nmap -p 902 -iL $1 -Pn -sT -sV  -vv --open --script=vmware-version.nse,vmauthd-brute.nse --script-args ssh-brute.timeout=5s -oN ./Vmware_Exsi_login.txt >/dev/null 2>&1
		echo -e "\033[35mVmware Exsi 爆破完毕 ! 结果已存到当前目录的Vmware_Exsi_login.txt文件中\033[0m"
    fi
	
done < targetports.txt

