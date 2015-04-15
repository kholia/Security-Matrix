#!/usr/bin/env python

import sys

# Initialize Site object
import mwclient
site = mwclient.Site(host='localhost', path="/wiki/")
#site.login("XXX", "XXX")

# Edit page
page = site.Pages['Features']
old_text = page.edit()

new_text = sys.stdin.read()

with open("upstream.txt", "w") as f:
    f.write(old_text)

with open("local.txt", "w") as f:
    f.write(new_text)

if old_text != new_text:
    print "Content is different!"

# page.save(new_text, summary = 'Security Matrix')
