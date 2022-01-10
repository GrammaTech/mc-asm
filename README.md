# mc-asm

mc-asm provides a C and Python API for turning assembly into machine code,
providing rich symbolic information.

## Copyright and Acknowledgments

Copyright (C) 2020 GrammaTech, Inc.

This code is licensed under the MIT license. See the LICENSE file in
the project root for license terms.

This project is sponsored by the Office of Naval Research, One Liberty
Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
N68335-17-C-0700.  The content of the information does not necessarily
reflect the position or policy of the Government and no official
endorsement should be inferred.

The header files under the `src/llvm-headers/` directory are copied from the
LLVM project and are licensed under the Apache License v2.0 with LLVM
Exceptions (a copy of that license is included in the `src/llvm-headers/`
directory).

The following files from the open-source LLVM project are included in the
MCASM repository.
* Files:
  - AArch64MCExpr.h (from `llvm/lib/Target/AArch64/MCTargetDesc/`)
  - MipsMCExpr.h (from `llvm/lib/Target/Mips/MCTargetDesc/`)
* Project Name: LLVM
* Project Version: 13.0
* License: Apache License v2.0 with LLVM Exceptions
