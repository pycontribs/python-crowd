#!/usr/bin/env python

import crowd
import os, sys, getpass

app_url = 'http://my.crowd.server:8095/crowd/'
app_user = 'testapp'
app_pass = 'testpass'

# Create the reusable Crowd object
cs = crowd.CrowdServer(app_url, app_user, app_pass)

if len(sys.argv) > 1:
    username = sys.argv[1]
else:
    username = os.environ['USER']

password = getpass.getpass(prompt='Enter password for %s: ' % username)

success = cs.auth_user(username, password)
if success:
    print 'Successfully authenticated.'
else:
    print 'Failed to authenticate.'
