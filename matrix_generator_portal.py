#!/usr/bin/env python

# Copyright 2008-2010 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
#
# Shamelessly stolen for Fedora
# Copyright 2013 Dhiru Kholia
# License: GPLv3

import sys
import json
import subprocess
import json

from lib import features, releases, color

# import "raw" data
from data import feature_list

target = sys.stdout

# start generating markup, the legend comes first.
target.write("""

<table style="width: 100px;">
<tr style="background: #00dd00;">
<td> By Default
</td></tr>
<tr style="background: #98fd98;">
<td> Available
</td></tr>
<tr style="background: #ffff00;">
<td> Unimplemented
</td></tr>
</table>

<style>

hr {color:sienna;}
p {margin-left:20px;}

table { margin: 1em 0; background-color: #f9f9f9; border: 1px #aaa solid;
             border-collapse: collapse; color: black; }

td { border: 1px #aaa solid; padding: 0.2em; }

</style>

<table>
<tr>
<td> Security Features  </td>

""")

# release name headers
for rel in releases:
    target.write(' <td> %-20s </td>\n' % (rel))
target.write("</tr>")

# features part of various releases
for details in feature_list:
    if "section" in details:
        continue
    if "skip" in details:
        continue

    name = details['name']
    short = details['short']

    target.write("\n    <tr>\n")
    target.write(
        '\n<td> <a href="#%s"> %20s  </td>\n' %
        (short, features[name]['short']))

    for rel in releases:
        item = features[name]['matrix'][rel]
        target.write(
            '<td style="background:#%s"> %-20s </td>\n' %
            (color[item['state']], item['status']))
    target.write('</tr>\n')

# start descriptions

target.write('</table>\n')

cmd = "ruby ./wikicloth_filter.rb"

for details in feature_list:
    if "section" in details:
        continue

    name = details['name']
    short = details['short']
    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    p.stdin.write(features[name]['desc'])
    o, e = p.communicate()
    o = o.replace("<code>", "<code> <pre>")
    o = o.replace("</code>", "</pre> </code>")

    target.write('<h3> <span id="%s"> %s </span></h3>\n' %
                 (features[name]['short'], features[name]['short']))

    target.write('%s\n\n' % (o))

target.flush()
