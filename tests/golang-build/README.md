Golang build test
=================

This just builds go version 1.16.6, and then makes sure we can a basic go
program with the build toolchain.

Building this version of go tests the following kernel fixes:
  - `a88603f4b92e ("powerpc/vdso: Don't use r30 to avoid breaking Go lang")`
  - `4a5cb51f3db4 ("powerpc/64s/interrupt: Fix check_return_regs_valid() false positive")`
