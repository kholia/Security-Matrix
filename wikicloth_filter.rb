#!/usr/bin/env ruby

require 'wikicloth'

data = ARGF.read

wiki = WikiCloth::Parser.new(:data => data)
print wiki.to_html
