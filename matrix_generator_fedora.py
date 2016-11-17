#!/usr/bin/env python

# Copyright 2008-2010 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
#
# Shamelessly stolen for Fedora
# Copyright 2013 Dhiru Kholia
# License: GPLv3

import sys

# import "raw" data
from data import feature_list
from lib import *

target = sys.stdout

# start generating markup, the legend comes first.
target.write("""

__NOEDITSECTION__
__NONEWSECTIONLINK__

{| class="wikitable"
|- style="background: #00dd00;"
| By Default
|- style="background: #98fd98;"
| Available
|- style="background: #ffff00;"
| Unimplemented
|}

{| class="wikitable"
| Security Features """
)

# release name headers
for rel in releases:
    target.write(' || %-20s' % (rel))
target.write("\n|-\n")

# features part of various releases
for details in feature_list:
    if "section" in details:
        continue
    if "skip" in details:
        continue

    name = details['name']
    short = details['short']
    target.write(
        '| [[#%s|%20s]]     ' %
        (short, features[name]['short']))

    for rel in releases:
        item = features[name]['matrix'][rel]
        target.write(
            '|| style="background:#%s" | %-20s' %
            (color[item['state']], item['status']))
    target.write('\n|-\n')
target.write("|}")

# start descriptions
# target.write('\n== Features ==\n\n')

# configure TOC's placement
target.write("""\n<div style="float:right;">__TOC__</div>\n""")

for details in feature_list:
    name = details['name']
    short = details['short']
    depth = '=' * (features[name]['depth'] + 2)

    target.write('%s %s %s\n' % (depth, features[name]['short'], depth))
    target.write('%s\n\n' % (features[name]['desc']))

target.flush()
