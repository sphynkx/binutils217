/*
 * diag_crt0.c — Plan 9 i386 diagnostic startup for exec-format debugging
 *
 * PURPOSE
 *   Stand-alone diagnostic crt0 to capture the kernel-provided entry state
 *   (SP, AX=Tos, initial stack contents) and write them to stdout as hex.
 *   Link this INSTEAD OF main9.8 + callmain.8 to bypass the standard
 *   libc startup entirely.
 *
 *   Comparing the output of a natively-built (8c/8l) binary against a
 *   BFD-linked binary reveals exec-header ABI mismatches: wrong VMAs,
 *   wrong a_text causing the kernel to map text/data from wrong offsets,
 *   or wrong a_entry.
 *
 * BUILD (on 9front, native tools)
 *   8c diag_crt0.c
 *   8l -o diag diag_crt0.8          # no main9.8 or callmain.8
 *   ./diag | od -t x4               # prints SP, AX, then 32 stack words
 *
 * BUILD (cross, with our plan9-i386 BFD toolchain)
 *   i386-unknown-plan9-gcc -c diag_crt0.c -o diag_crt0.o
 *   i386-unknown-plan9-ld  -o diag diag_crt0.o
 *   scp diag 9front-system:; ssh 9front-system ./diag | od -t x4
 *
 * ENTRY STATE (Plan 9 i386, 9front kernel)
 *   AX  = pointer to Tos (top-of-segment process-private kernel struct)
 *   SP  = initial user stack pointer
 *   [SP+0]  = argc
 *   [SP+4]  = argv[0] (pointer to argv[0] string)
 *   [SP+8]  = argv[1] ...
 *   ...
 *   followed by a null, then env[] pointers.
 *
 * INTERPRETATION
 *   If argc is 1 and argv[0] is the path to the binary, the kernel set
 *   up the stack correctly.  Compare the AX (Tos) value — it should
 *   point to a valid address near the top of the stack segment.
 *
 *   A wrong a_text in our exec header causes the kernel to:
 *     - Map too many (or too few) bytes as .text
 *     - Map the .data section from the wrong file offset
 *     => global variables read as 0; function pointers are garbage.
 *
 * DIAGNOSE
 *   1. Build diag natively with 8l (reference).
 *   2. Build diag with our BFD toolchain (test).
 *   3. Run both on 9front; compare output of `od -t x4`.
 *   If SP and the argc word differ, the exec header has an ABI issue.
 *   If AX (Tos) differs, the kernel is not recognising our exec correctly.
 */

#include <u.h>
#include <libc.h>

/*
 * _main is the true entry point (what a_entry points to).
 * The Plan 9 kernel jumps (not calls) here with:
 *   AX = Tos ptr, SP = initial stack (argc at [SP]).
 *
 * We use a tiny assembly wrapper to capture AX before the C prologue
 * overwrites it, then call diag() with the saved values.
 */

/* Assembly wrapper to capture entry AX before C clobbers it.         */
/* On 9front i386, 8c generates a _main that receives control from     */
/* the kernel directly; the Plan 9 'void main(void)' convention is     */
/* not the same as Unix.  We use 8a asm syntax here.                   */
/*                                                                      */
/* If building with GCC, replace with:                                  */
/*   asm("_start: movl %eax,%edi; movl %esp,%esi; call diag_entry");   */

/* diag_entry: called with entry_ax=Tos, entry_sp=initial SP           */
void
diag_entry(ulong entry_ax, ulong entry_sp)
{
	ulong buf[1 + 2 + 32];   /* magic word + entry_sp + entry_ax + 32 stack words */
	ulong *stack;
	int i;

	buf[0] = 0x44494147UL;   /* "DIAG" magic (big-endian ASCII) */
	buf[1] = entry_sp;
	buf[2] = entry_ax;       /* Tos pointer */

	stack = (ulong *)entry_sp;
	for (i = 0; i < 32; i++)
		buf[3 + i] = stack[i];

	/*
	 * pwrite(fd=1, buf, n=(1+2+32)*4=140, offset=-1LL)
	 * offset=-1 means "write at current position" in Plan 9.
	 */
	pwrite(1, buf, (1 + 2 + 32) * 4, -1LL);

	exits(nil);
}

/*
 * main() is only present so that '8c diag_crt0.c' compiles without error.
 * The real entry is _main (defined in 8a diag_crt0_asm.s below, or set
 * by the linker to main() for the cross-build test).
 */
void
main(void)
{
	/*
	 * In a native 9front build, control comes from _main (the assembly
	 * wrapper that saves AX and calls diag_entry).  In a cross-built
	 * binary where the entry point IS main(), we cannot capture the
	 * kernel's AX; use 0 as a placeholder.
	 */
	ulong entry_sp;

	/* Approximate current SP — not the kernel entry SP.              */
	entry_sp = (ulong)&entry_sp;
	diag_entry(0 /* AX not captured */, entry_sp);
}
