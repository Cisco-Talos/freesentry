=====================================
Clang 3.5 (In-Progress) Release Notes
=====================================

.. contents::
   :local:
   :depth: 2

Written by the `LLVM Team <http://llvm.org/>`_

.. warning::

   These are in-progress notes for the upcoming Clang 3.5 release. You may
   prefer the `Clang 3.4 Release Notes
   <http://llvm.org/releases/3.4/tools/clang/docs/ReleaseNotes.html>`_.

Introduction
============

This document contains the release notes for the Clang C/C++/Objective-C
frontend, part of the LLVM Compiler Infrastructure, release 3.5. Here we
describe the status of Clang in some detail, including major
improvements from the previous release and new feature work. For the
general LLVM release notes, see `the LLVM
documentation <http://llvm.org/docs/ReleaseNotes.html>`_. All LLVM
releases may be downloaded from the `LLVM releases web
site <http://llvm.org/releases/>`_.

For more information about Clang or LLVM, including information about
the latest release, please check out the main please see the `Clang Web
Site <http://clang.llvm.org>`_ or the `LLVM Web
Site <http://llvm.org>`_.

Note that if you are reading this file from a Subversion checkout or the
main Clang web page, this document applies to the *next* release, not
the current one. To see the release notes for a specific release, please
see the `releases page <http://llvm.org/releases/>`_.

What's New in Clang 3.5?
========================

Some of the major new features and improvements to Clang are listed
here. Generic improvements to Clang as a whole or to its underlying
infrastructure are described first, followed by language-specific
sections with improvements to Clang's support for those languages.

Major New Features
------------------

- Clang uses the new MingW ABI
  GCC 4.7 changed the mingw ABI. Clang 3.4 and older use the GCC 4.6
  ABI. Clang 3.5 and newer use the GCC 4.7 abi.

- The __has_attribute feature test is now target-aware. Older versions of Clang
  would return true when the attribute spelling was known, regardless of whether
  the attribute was available to the specific target. Clang now returns true
  only when the attribute pertains to the current compilation target.
  
- Clang 3.5 now has parsing and semantic-analysis support for all OpenMP 3.1
  pragmas (except atomics and ordered). LLVM's OpenMP runtime library,
  originally developed by Intel, has been modified to work on ARM, PowerPC,
  as well as X86. Code generation support is minimal at this point and will
  continue to be developed for 3.6, along with the rest of OpenMP 3.1.
  Support for OpenMP 4.0 features, such as SIMD and target accelerator
  directives, is also in progress. Contributors to this work include AMD,
  Argonne National Lab., IBM, Intel, Texas Instruments, University of Houston
  and many others.

Improvements to Clang's diagnostics
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Clang's diagnostics are constantly being improved to catch more issues,
explain them more clearly, and provide more accurate source information
about them. The improvements since the 3.4 release include:

- GCC compatibility: Clang displays a warning on unsupported gcc
  optimization flags instead of an error.

- Remarks system: Clang supports `-R` flags for enabling remarks. These are
  diagnostic messages that provide information about the compilation process,
  but don't suggest that a problem has been detected. As such, they cannot
  be upgraded to errors with `-Werror` or `-Rerror`. A `-Reverything` flag
  is provided (paralleling `-Weverything`) to turn on all remarks.

- New remark `-Rpass`: Clang provides information about decisions made by
  optimization passes during compilation. See :ref:`opt_rpass`.

- New warning `-Wabsolute-value`: Clang warns about incorrect or useless usage
  of the absolute functions (`abs`, `fabsf`, etc).

  .. code-block:: c

    #include <stdlib.h>
    void foo() {
     unsigned int i=0;
     abs(i);
    }

  returns
  `warning: taking the absolute value of unsigned type 'unsigned int' has no effect [-Wabsolute-value]`

  or

  .. code-block:: c

    #include <stdlib.h>
    void plop() {
      long long i=0;
      abs(i);
    }

  returns
  `warning: absolute value function 'abs' given an argument of type 'long long' but has parameter of type 'int' which may cause truncation of value [-Wabsolute-value] use function 'llabs' instead`

- New warning `-Wtautological-pointer-compare`:

  .. code-block:: c++

    #include <stddef.h>
    void foo() {
     int arr[5];
     int x;
     // warn on these conditionals
     if (foo);
     if (arr);
     if (&x);
     if (foo == NULL);
     if (arr == NULL);
     if (&x == NULL);
    }

  returns
  `warning: comparison of address of 'x' equal to a null pointer is always false [-Wtautological-pointer-compare]`

- New warning `-Wtautological-undefined-compare`: 

  .. code-block:: c++

    #include <stddef.h>
    void f(int &x) {
       if (&x == nullptr) { }
    }

  returns
  `warning: reference cannot be bound to dereferenced null pointer in well-defined C++ code; comparison may be assumed to always evaluate to false [-Wtautological-undefined-compare]`

-  ...

New Compiler Flags
------------------

The integrated assembler is now turned on by default on ARM (and Thumb),
so the use of the option `-fintegrated-as` is now redundant on those
architectures. This is an important move to both *eat our own dog food*
and to ease cross-compilation tremendously.

We are aware of the problems that this may cause for code bases that
rely on specific GNU syntax or extensions, and we're working towards
getting them all fixed. Please, report bugs or feature requests if
you find anything. In the meantime, use `-fno-integrated-as` to revert
back the call to GNU assembler.

In order to provide better diagnostics, the integrated assembler validates
inline assembly when the integrated assembler is enabled.  Because this is
considered a feature of the compiler, it is controlled via the `fintegrated-as`
and `fno-integrated-as` flags which enable and disable the integrated assembler
respectively.  `-integrated-as` and `-no-integrated-as` are now considered
legacy flags (but are available as an alias to prevent breaking existing users),
and users are encouraged to switch to the equivalent new feature flag.

Deprecated flags `-faddress-sanitizer`, `-fthread-sanitizer`,
`-fcatch-undefined-behavior` and `-fbounds-checking` were removed in favor of
`-fsanitize=` family of flags.

It is now possible to get optimization reports from the major transformation
passes via three new flags: `-Rpass`, `-Rpass-missed` and `-Rpass-analysis`.
These flags take a POSIX regular expression which indicates the name
of the pass (or passes) that should emit optimization remarks.

Options `-u` and `-z` are forwarded to the linker on gnutools toolchains.


New Pragmas in Clang
-----------------------

Loop optimization hints can be specified using the new `#pragma clang loop`
directive just prior to the desired loop. The directive allows vectorization and
interleaving to be enabled or disabled. Vector width as well as interleave count
can be manually specified.  See :ref:`langext-pragma-loop` for details.

C Language Changes in Clang
---------------------------

...

C11 Feature Support
^^^^^^^^^^^^^^^^^^^

...

C++ Language Changes in Clang
-----------------------------

- Reference parameters and return values from functions are more aggressively
  assumed to refer to valid objects when optimizing. Clang will attempt to
  issue a warning by default if it sees null checks being performed on
  references, and `-fsanitize=null` can be used to detect null references
  being formed at runtime.

- ...

C++17 Feature Support
^^^^^^^^^^^^^^^^^^^^^

Clang has experimental support for some proposed C++1z (tentatively, C++17)
features. This support can be enabled using the `-std=c++1z` flag. The
supported features are:

- `static_assert(expr)` with no message

- `for (identifier : range)` as a synonym for `for (auto &&identifier : range)`

- `template<template<...> typename>` as a synonym for `template<template<...> class>`

Additionally, trigraphs are not recognized by default in this mode.
`-ftrigraphs` can be used if you need to parse legacy code that uses trigraphs.
Note that these features may be changed or removed in future Clang releases
without notice.

Objective-C Language Changes in Clang
-------------------------------------

...

OpenCL C Language Changes in Clang
----------------------------------

...

OpenMP C/C++ Language Changes in Clang
--------------------------------------

- `Status of supported OpenMP constructs 
  <https://github.com/clang-omp/clang/wiki/Status-of-supported-OpenMP-constructs>`_.


Internal API Changes
--------------------

These are major API changes that have happened since the 3.4 release of
Clang. If upgrading an external codebase that uses Clang as a library,
this section should help get you past the largest hurdles of upgrading.

- Clang uses `std::unique_ptr<T>` in many places where it used to use
  raw `T *` pointers.

libclang
--------

...

Static Analyzer
---------------

Check for code testing a variable for 0 after using it as a denominator.
This new checker, alpha.core.TestAfterDivZero, catches issues like this:

.. code-block:: c

  int sum = ...
  int avg = sum / count; // potential division by zero...
  if (count == 0) { ... } // ...caught here


The `-analyzer-config` options are now passed from scan-build through to
ccc-analyzer and then to Clang.

With the option `-analyzer-config stable-report-filename=true`,
instead of `report-XXXXXX.html`, scan-build/clang analyzer generate
`report-<filename>-<function, method name>-<function position>-<id>.html`.
(id = i++ for several issues found in the same function/method).

List the function/method name in the index page of scan-build.

...

Core Analysis Improvements
==========================

- ...

New Issues Found
================

- ...

Python Binding Changes
----------------------

The following methods have been added:

-  ...

Significant Known Problems
==========================

Additional Information
======================

A wide variety of additional information is available on the `Clang web
page <http://clang.llvm.org/>`_. The web page contains versions of the
API documentation which are up-to-date with the Subversion version of
the source code. You can access versions of these documents specific to
this release by going into the "``clang/docs/``" directory in the Clang
tree.

If you have any questions or comments about Clang, please feel free to
contact us via the `mailing
list <http://lists.cs.uiuc.edu/mailman/listinfo/cfe-dev>`_.
