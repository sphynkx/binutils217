/* te-plan9_i386.h -- Plan 9 i386 target environment for GAS.  */

#ifndef TE_PLAN9_I386_H
#define TE_PLAN9_I386_H

#include "te-generic.h"

/* BFD target name to use when creating output files.  */
#ifndef TARGET_FORMAT
#define TARGET_FORMAT "plan9-i386"
#endif

/* Used by tc-i386.h (EXTERN_FORCE_RELOC/S_FORCE_RELOC logic).  */
#ifndef OUTPUT_FLAVOR
#define OUTPUT_FLAVOR bfd_target_aout_flavour
#endif

#endif /* TE_PLAN9_I386_H */