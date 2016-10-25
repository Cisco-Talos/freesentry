Copyright 2015 Cisco Systems.

Disclaimer: This is alpha software, it might not work as expected, use at your own risk.

Build and install the LLVM in above directory as you normally would
In this directory (installs to /usr/local/lib and /usr/local/share/freesentry by default):
```	$ make
	# make install
```

To compile something, you'll need to build it twice if this is the first time ever you're building it with FreeSentry.
We need to do this so we can extract the callgraph the first time. The reason we can't do this on the fly is 
that we need information on functions that are in all possible source files, while the compiler generally handles 
files one by one.

So to get the call graph we need to set the following environment variables:
```
$ mkdir -p /var/tmp/freesentry
$ rm -f /var/tmp/freesentry/PROGNAME.raw
$ export CC=clang
$ export CFLAGS="-O2 -mllvm -fsg -mllvm -fsgout=/var/tmp/freesentry/PROGNAME.raw"
$ export CXX=clang++
$ export CXXFLAGS="-O2 -mllvm -fsg -mllvm -fsgout=/var/tmp/freesentry/PROGNAME.raw"
```

Run your normal build commands.

Next we need to resolve the calls to give us our call model:
```
./resolvecalls def /var/tmp/freesentry/PROGNAME.raw /var/tmp/freesentry/PROGNAME.res
```

You can copy over the resolved filename to /usr/local/share/freesentry since it only 
needs to be run once (unless there's changes to the function calls you do in the code).

Important note: from a security standpoint it's better to run without a call model 
than it is to run with one that's outdated. If the model is outdated, we might 
mistakenly assume that a function doesn't call free, when that behaviour has changed.

If you do not create a call model, then we simply assume that all functions call free.
This sacrifices performance for security.

Once the build is complete, we need to rebuild with the mitigation enabled: 
```
$ make clean
$ export CC=clang
$ export CFLAGS="-O2 -mllvm -fs -mllvm -fsl -mllvm -fsgin=/var/tmp/freesentry/PROGNAME.res"
$ export CXX=clang++
$ export CXXFLAGS="-O2 -mllvm -fs -mllvm -fsl -mllvm -fsgin=/var/tmp/freesentry/PROGNAME.res"
$ export LDFLAGS="-lfreesentry -ldlmalloc32b"
```

Perform your regular build commands once again.

It is important to enable at least -O1 for both passes, if no optimization is 
specified then LLVM will not call any of the transformations that it normally does 
and it won't call ours either.

For questions or to report issues, please email freesentry@fort-knox.org

More information is available here:

Blog post: http://blogs.cisco.com/security/talos/freesentry

NDSS paper: FreeSentry/ndss15.pdf

CanSecWest slides: FreeSentry/cansec15.pdf

The blog post contains the most recent information on the mitigation.
