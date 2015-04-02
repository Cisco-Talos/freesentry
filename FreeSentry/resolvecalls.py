#!/usr/bin/python
import sys
from collections import defaultdict
d = defaultdict(set)


type = sys.argv[1]
infile = sys.argv[2]
outfile = sys.argv[3]

if type == "undefined":
	trackundefined = True
else:
	trackundefined = False

unresolved = {}


with open(infile) as fd:
    for line in fd:
       line = line.strip()
       if line:
	try:
       	   key, spacedvalues = line.split(":",1)
           values = spacedvalues.split()
	   if key in d:
	      saved, handled = d[key]
	      saved.update(values)
	   else:
              d[key] = set(values), set()
	except ValueError:
	   continue


libs = {}
with open("/usr/local/share/freesentry/callmodel.res") as fd:
    for line in fd:
	key, val = line.strip().split()
	libs[key] = val

# 0 for no calls to free
# 1 for calls to free
resolved = {}

def firstpass():
	for key in d:
		if key in resolved:
			continue
		values, handled = d[key]
		# remove recursive calls
		if key in values:
			values.remove(key)
		# leaf functions can be resolved 
		if not values:
			resolved[key] = 0
			continue


def doresolve():
	for key in d:
		if key in resolved:
			continue
		values, handled = d[key]
		# remove recursive calls
		if key in values:
			values.remove(key)
		# leaf functions can be resolved 
		if not values:
			resolved[key] = 0
			continue


		savedvalues = values.copy()

		for func in values:
			savedvalues.remove(func)
			handled.add(func)
			if func in resolved:
				if resolved[func] == 1:
					resolved[key] = 1
					savedvalues = set()
					break
				#else:
				#	print "Removing", func
			elif func in d:
				v, i = d[func]
				newvalues = v.copy()
				for newfunc in v:
					# make sure we don't keep expanding functions
					# once a function has been expanded for a particular 
					#function, there is no need to expand it again
					if newfunc in handled:
						newvalues.remove(newfunc)
				if key in resolved:
					if resolved[key] == 1:
						break
				if key in newvalues:
					newvalues.remove(key)
				savedvalues.update(newvalues)
			elif func in libs:
				if libs[func] == "1":
					resolved[key] = 1
					savedvalues = set()
					break
			else:
				# unresolved function, probably a library call we don't know about, play it safe
				if trackundefined:
					unresolved[func] = 0
				else:
					resolved[key] = 1
					savedvalues = set()
					break

		d[key] = savedvalues, handled


while (1):
	print "Resolving..."
	doresolve()
	done = 1
	for key in d:
		values, handled = d[key]
		if values or (key not in resolved):
			done = 0
			break
	if done:
		break	

with open(outfile, "w") as fd:
    if "<indirect>" in resolved:
    	del resolved["<indirect>"]

    if trackundefined:
	outdict = unresolved
    else:
	outdict = resolved

    for p in outdict.items():
	fd.write("%s %s\n" %p)
