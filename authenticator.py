#!/usr/bin/env python2
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is the authenticator.py.
#
# The Initial Developer of the Original Code is
# kang@insecure.ws
# Portions created by the Initial Developer are Copyright (C) 2013
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# Mozilla Corporation - gdestuynder@mozilla.com
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.

import time
import signal
import hmac
import base64
import struct
import hashlib
import os
import stat
import sys
import getpass

# Google-Authenticator compatible TOTP validator
# Store the seed in $HOME/.totp, chmod 0600 $HOME/.totp to use
# Use a seed of ~16 char long, pairs. uneven amount of chars will fail the base32 decoding
# and be refused by the Google Authenticator as well.
# Tokens can also be generated with oathtoolkit -b --totp <SEED>
# By default, tokens up to 60s old, or 90s new are accepted
# kang@insecure.ws

def signal_handler(signal, f):
    failure('User cancelled.')

	signal.signal(signal.SIGINT, signal_handler)

def totp_gauth_gen(seed, stamp=int(time.time()//30)):
	data = struct.pack(">Q", stamp)
	key = base64.b32decode(seed, True)
	hmac_value = hmac.new(key, data, hashlib.sha1).digest()
	buf = ord(hmac_value[19]) & 15
	res = (struct.unpack(">I", hmac_value[buf:buf+4])[0] & 0x7fffffff) % 1000000
	return res

def get_user_seed(filename=os.environ['HOME']+'/.totp'):
	try:
		fd = open(filename)
	except IOError:
		failure('No seed on system. Authentication impossible.')

	st = os.stat(filename)
	if bool(st.st_mode & stat.S_IRGRP) or bool(st.st_mode & stat.S_IROTH):
		failure('Permissions too open on %s' % filename)

	line = fd.readline()
	seed = None
	while line != '':
		if line.startswith('#'):
			continue
		line = line.split('\n')[0]
		line = line.split('#')[0]
		try:
			base64.b32decode(line, True)
			seed = line
		except:
			continue
		line = fd.readline()
	return seed

def failure(msg):
	print("Authentication failed: %s" % msg)
	sys.exit(1)

def check_token(secret, seed):
	#allow passwords from past 60s, future 60s and current 30s (2min30 total window)
	for i in range(-2,2):
		token = totp_gauth_gen(seed, int(time.time()//30)+i)
		if str(secret) == str(token):
			return True
	return False

def start_shell():
	if os.environ.has_key('SHELL'):
		os.execv(os.environ['SHELL'], [os.environ['SHELL']])
	else:
		os.execv('/bin/bash', '/bin/bash')

def get_token():
	return getpass.getpass('Token: ')

def main():
	seed = get_user_seed()
	if seed == None:
		failure('Couldn\'t find your TOTP seed.')

	secret = get_token()

	if not check_token(secret, seed):
		failure('Incorrect token.')
	else:
		start_shell()

if __name__ == "__main__":
	main()
	sys.exit(1)
