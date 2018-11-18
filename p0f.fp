#
# p0f - passive OS fingerprinting
#
# Valid entry describes the way server starts TCP handshake (first SYN).
# Important options are: window size (wss), maximum segment size (mss),
# don't fragment flag (DF), window scaling (wscale), sackOK flag, nop
# flag, and initial time to live (TTL) ;)
#
# How can you determine initial ttl? Well, usually it's first power of 2
# bigger than TTL returned in scan. So, for example, if you get TTL 55 in
# fingerprint returned by p0f, initial TTL will be usually 64... NOTE:
# it's better to overestimate initial TTL than underestimate it ;)
#
# There are some brain-damaged devices, like network printers etc, that
# have stupid initial TTLs like 60, but who cares, if HP LaserJet wants to
# visit your server, you have to think again about your life ;)
#
# Format:
#
# wwww:ttt:mmm:D:W:S:N:OS Description
#
# wwww - window size
# ttt  - time to live
# mmm  - maximum segment size
# D    - don't fragment flag  (0=unset, 1=set) 
# W    - window scaling (-1=not present, other=value)
# S    - sackOK flag (0=unset, 1=set)
# N    - nop flag (0=unset, 1=set)
#

31072:64:3884:1:0:1:1:Linux 2.2.12-20 (RH 6.1)
512:64:1460:0:0:0:0:Linux 2.0.38
32120:64:1460:1:0:1:1:Linux 2.2.14 or Cobalt Linux 2.2.12C3
16384:64:1460:1:0:0:0:FreeBSD 4.0-STABLE, 3.2-RELEASE
8760:64:1460:1:0:0:0:Solaris 2.6 (2)
9140:255:9140:1:0:0:0:Solaris 2.6 (sunsite)
49152:64:1460:0:0:0:0:IRIX 6.5 / 6.4
8760:255:1460:1:0:0:0:Solaris 2.6 or 2.7
8192:128:1460:1:0:0:0:Windows NT 4.0
8192:128:1460:1:0:1:1:Windows 9x (1)
8192:128:536:1:0:1:1:Windows 9x (2)
2144:64:536:1:0:1:1:Windows 9x (4)
16384:128:1460:1:0:1:1:Windows 2000
32120:32:1460:1:0:1:1:Linux 2.2.13
8192:32:1460:1:0:0:0:Windows NT 4.0
5840:128:536:1:0:1:1:Windows 95 (3)
16060:64:1460:1:0:1:1:Debian/Caldera Linux 2.2.x (check)
8760:255:1380:1:0:0:0:Solaris 2.7
8192:128:1456:1:0:1:1:Linux 2.2.13
32768:64:1432:0:0:0:0:??? (PlusGSM, InterNetia proxy)
16384:255:1460:1:0:0:1:FreeBSD 2.2.6-RELEASE
8192:64:1460:1:0:0:1:BSDI BSD/OS 3.1
16384:64:1460:0:0:0:1:NetBSD 1.3/i386
24820:64:1460:1:0:0:0:SCO UnixWare 7.0.1
32768:64:1460:1:0:0:0:HP-UX B.10.01 A 9000/712
16384:64:512:0:0:0:0:AIX 3.2, 4.2 - 4.3
32768:64:1460:1:0:0:1:Digital UNIX V4.0E
32694:255:536:0:0:0:0:3Com HiPer ARC, System V4.2.32
4128:255:556:0:0:0:0:Cisco 1750 IOS 12.0(5), Cisco 2500 IOS 11.3(1)
4128:255:556:0:0:0:0:Cisco 3600 IOS Version 12.0(7)
4288:255:1460:0:-1:0:0:Cisco 3620 IOS 11.2(17)P
512:64:0:0:-1:0:0:Linux 2.0.35 - 2.0.37
8192:128:1460:1:-1:1:0:Windows NT 
32120:64:1460:1:190:1:1:Linux 2.2.16
32696:64:536:0:0:1:1:SCO UnixWare 7.1.0 x86
24820:64:1460:1:0:0:1:SCO UnixWare 7.1.0 x86
32120:58:1460:0:-1:0:0:Linux 2.0.38
65535:128:1368:1:-1:0:0:BorderManager 3.5
33580:255:1460:1:-1:0:0:Solaris 7
8192:128:25443:1:-1:1:1:Microsoft NT 4.0 Server SP5
8192:64:1460:1:-1:0:0:AXCENT Raptor Firewall Windows NT 4.0/SP3
8192:32:1456:1:-1:0:0:Windows 95 (?)
16384:64:0:0:-1:0:0:ULTRIX V4.5 (Rev. 47)
16384:64:512:0:0:0:1:OpenBSD 2.6
32768:128:1460:1:-1:0:0:Novell NetWare 4.11
16384:64:1460:1:0:0:1:FreeBSD 2.2.8-RELEASE
4288:255:536:0:-1:0:0:Cisco 1600 IOS 11.2(15)P
4096:32:1024:0:245:0:0:Alcatel (Xylan) OmniStack 5024
4288:255:536:0:-1:0:0:Cisco 2500 IOS 11.2(5)P or Cisco 4500 IOS 11.1(7)
2144:255:536:0:-1:0:0:Cisco IGS 3000 IOS 11.x(16), 2500 IOS 11.2(3)P
4128:255:1460:0:-1:0:0:Cisco 2611 IOS 11.3(2)XA4
61440:64:1460:0:-1:0:0:IRIX 6.3
61440:64:512:0:-1:0:0:IRIX 5.3 / 4.0.5F
4128:255:1460:0:-1:0:0:Cisco C2600 IOS 12.0(5)T1
31856:64:1460:1:0:1:1:Linux 2.4.0-test1
4096:30:1024:0:245:0:0:Alcatel (Xylan) OmniStack 5024 v3.4.5
4096:30:1024:0:-1:0:0:Chorus MiX V.3.2 r4.1.5 COMP-386
4128:255:1460:0:-1:0:0:Cisco 4500 IOS 12.0(9), 3640 12.1(2), 3620 12.0(8) or 11.3(11a)
32120:64:1460:1:101:1:1:Linux 2.2.15
32120:64:1460:0:-1:0:0:Linux 2.0.33
512:64:1460:0:52:0:0:Linux 2.0.33

