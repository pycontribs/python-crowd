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

# Create a session. The important bit is the token.
session = cs.get_session(username, password)
if session:
    print 'Created a session, token %s' % session['token']
else:
    print 'Failed to authenticate.'
    sys.exit(1)

# Check that the token is valid (and of course it should be).
success = cs.validate_session(session['token'])
if success:
    print 'Authenticated session token.'
else:
    print 'Failed to authenticate token.'
