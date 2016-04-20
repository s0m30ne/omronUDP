Using nmap --script omronudp-info -sU -p 9600 <HOST> to scan a target for it's controller
information.

    root@kali:~# nmap --script omronudp-info -sU -p 9600 ***.***.***.***
    
    Starting Nmap 6.47 ( http://nmap.org ) at 2016-04-20 15:31 CST
    Nmap scan report for ***.***.***.***
    Host is up (0.00087s latency).
    PORT     STATE         SERVICE
    9600/udp open|filtered unknown
    | omronudp-info: 
    |   Controller Model: CJ2H-CPU65-EIP      01.90
    |   Controller Version: 01.90
    |   For System Use: 
    |   Program Area Size: 200
    |   IOM size: 23
    |   No. DM Words: 32768
    |   Timer/Counter: 8
    |   Expansion DM Size: 4
    |   No. of steps/transitions: 0
    |   Kind of Memory Card: No Memory Card
    |_  Memory Card Size: 0
    
    Nmap done: 1 IP address (1 host up) scanned in 4.53 seconds

Using python omron.py <HOST> to scan a target for it's controller
information.

    root@kali:~# python omron.py ***.***.***.***
    Host is up (0.114000s latency)
    PORT       STATE    SERVICE
    9600/udp   open      OMRON
    | OMRON Controller info:
    |   Controller Model: CJ2H-CPU65-EIP
    |   Controller Version: 01.90
    |   For System Use:
    |   Program Area Size: 200
    |   IOM Size: 23
    |   No. DM Words: 32768
    |   Timer/Counter: 8
    |   Expansion DM Size: 4
    |   No. of steps/transitions: 0
    |   Kind of Memory Card: No Memory Card
    |_  Memory Card Size: 0