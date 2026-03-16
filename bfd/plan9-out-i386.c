/* BFD back-end for Plan 9 i386 "out" object files (.8 format).
   Copyright (C) 2024 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
   USA.  */

/* Plan 9 i386 object files are produced by the 8c compiler and 8a assembler.
   They use a stream-based record format (NOT a.out) where each record starts
   with a 2-byte little-endian opcode.

   Detection heuristic (matching 9front isobjfile()):
     bytes[0]==0x7e, bytes[1]==0x00  (ANAME opcode = 126)
     bytes[3]==1 && bytes[4]=='<'   (first ANAME is D_FILE with name starting '<')

   Record encoding:
   - ANAME/ASIGNAME: [2-byte opcode LE][1-byte type][1-byte sym_index][NUL-terminated name]
     ASIGNAME also has [4-byte LE signature] before type/sym fields.
   - Other instructions: [2-byte opcode LE][4-byte line LE][from_zaddr][to_zaddr]

   zaddr encoding:
     [1-byte flags]: T_TYPE(1), T_INDEX(2), T_OFFSET(4), T_FCONST(8), T_SYM(16), T_SCONST(32)
     if T_INDEX: +2 bytes (index, scale)
     if T_OFFSET: +4 bytes (offset LE)
     if T_SYM: +1 byte (sym_index)
     if T_FCONST: +8 bytes (IEEE float)
     else if T_SCONST: +8 bytes (string constant, NSNAME=8)
     if T_TYPE: +1 byte (type)  */

#include "bfd.h"
#include "sysdep.h"
#include "libbfd.h"

/* Opcodes from 9front sys/src/cmd/8c/8.out.h (enum as) */
#define P9OBJ_ANAME      126   /* = 0x7e, symbol name record */
#define P9OBJ_ADATA       45   /* initialized data */
#define P9OBJ_AGLOBL      53   /* global (BSS) declaration */
#define P9OBJ_AHISTORY    55   /* source file history */
#define P9OBJ_ATEXT      220   /* function/text definition */
#define P9OBJ_AEND       329   /* end of object section */
#define P9OBJ_ASIGNAME   332   /* like ANAME but with signature */

/* D_* address types from 9front sys/src/cmd/8c/8.out.h (enum D_*) */
#define P9OBJ_D_EXTERN    61   /* external/global symbol */
#define P9OBJ_D_STATIC    62   /* static/local symbol */
#define P9OBJ_D_FILE      69   /* source file name fragment */
#define P9OBJ_D_FILE1     70   /* source file name continuation */

/* zaddr flags from l.h (T_* constants) */
#define P9OBJ_T_TYPE    (1 << 0)
#define P9OBJ_T_INDEX   (1 << 1)
#define P9OBJ_T_OFFSET  (1 << 2)
#define P9OBJ_T_FCONST  (1 << 3)
#define P9OBJ_T_SYM     (1 << 4)
#define P9OBJ_T_SCONST  (1 << 5)

/* Maximum symbol name length we'll accept (sanity check) */
#define P9OBJ_MAX_NAMELEN 4096

/* NSNAME constant (size of sconst field) */
#define P9OBJ_NSNAME     8

/* Symbol table entry during scanning */
struct p9sym_entry
{
  unsigned int  dtype;    /* D_EXTERN or D_STATIC */
  unsigned int  idx;      /* symbol index (h[idx]) */
  const char   *name;     /* pointer into strtab */
  asection     *section;  /* bfd section (text/data/bss/und) */
  bfd_vma       value;    /* symbol value (0 for objects) */
};

/* Private per-bfd data */
struct plan9_out_i386_tdata
{
  unsigned int   nsyms;
  asymbol       *symbols;   /* array of nsyms asymbol objects */
  char          *strtab;    /* heap-allocated string storage */
  bfd_size_type  strtab_len;

  /* Phase 2: generated section content from instruction encoding */
  int            encoded;          /* non-zero once encoding is done */
  bfd_byte      *text_content;     /* generated .text machine code */
  bfd_size_type  text_size;
  bfd_byte      *data_content;     /* generated .data bytes */
  bfd_size_type  data_size;
  bfd_size_type  bss_size;

  /* Per-section relocation arrays (for the linker) */
  struct plan9_out_i386_reloc *text_relocs;
  unsigned int   text_nrelocs;
  struct plan9_out_i386_reloc *data_relocs;
  unsigned int   data_nrelocs;

  /* Pointer array: sym_ptrs[i] = &symbols[i]; needed for arelent.sym_ptr_ptr */
  asymbol      **sym_ptrs;
};

/* One relocation record produced by the encoder. */
struct plan9_out_i386_reloc
{
  long      section_offset;  /* byte offset within section */
  int       sym_idx;         /* index into tdata->symbols[] */
  int       pc_relative;     /* 1 = PC-relative, 0 = absolute */
};

#define plan9_out_i386_tdata(abfd) \
  ((struct plan9_out_i386_tdata *) (abfd)->tdata.any)

/* --------------------------------------------------------------------- */
/* Return the number of bytes consumed by a zaddr encoding starting at p.
   Returns -1 on error (insufficient data or corrupt flags).  */

static int
p9obj_zaddr_size (const unsigned char *p, bfd_size_type rem)
{
  unsigned int t, c;

  if (rem < 1)
    return -1;

  t = p[0];
  c = 1;

  if (t & P9OBJ_T_INDEX)
    c += 2;
  if (t & P9OBJ_T_OFFSET)
    c += 4;
  if (t & P9OBJ_T_SYM)
    c += 1;
  if (t & P9OBJ_T_FCONST)
    c += 8;
  else if (t & P9OBJ_T_SCONST)
    c += P9OBJ_NSNAME;
  if (t & P9OBJ_T_TYPE)
    c += 1;

  if (c > rem)
    return -1;

  return (int) c;
}

/* Return the sym_index referenced by a zaddr starting at p, or -1 if none. */
static int
p9obj_zaddr_symidx (const unsigned char *p, bfd_size_type rem)
{
  unsigned int t, c;

  if (rem < 1)
    return -1;

  t = p[0];
  c = 1;

  if (t & P9OBJ_T_INDEX)
    c += 2;
  if (t & P9OBJ_T_OFFSET)
    c += 4;
  if (t & P9OBJ_T_SYM)
    {
      if (c >= rem)
        return -1;
      return (int) p[c];
    }
  return -1;
}

/* --------------------------------------------------------------------- */
/* Scan the object file stream and build the symbol table.
   Returns TRUE on success.  */

static bfd_boolean
p9obj_slurp_symtab (bfd *abfd)
{
  struct plan9_out_i386_tdata *tdata = plan9_out_i386_tdata (abfd);
  bfd_byte *buf = NULL;
  bfd_size_type size, pos;
  /* Temporary per-index entry: dtype and name index into strtab */
  struct p9sym_entry h[256];  /* up to 256 active symbols by index */
  unsigned int nsyms_found;
  /* Dynamic arrays */
  struct p9sym_entry *found_syms = NULL;
  unsigned int found_cap = 0;
  char *strtab = NULL;
  bfd_size_type strtab_size = 0, strtab_used = 0;
  unsigned int i;

  if (tdata->symbols != NULL)
    return TRUE;  /* already done */

  /* Read entire file into memory */
  if (bfd_seek (abfd, 0, SEEK_SET) != 0)
    return FALSE;

  size = bfd_get_size (abfd);
  if (size == 0)
    return TRUE;

  buf = (bfd_byte *) bfd_malloc (size);
  if (buf == NULL)
    return FALSE;

  if (bfd_bread (buf, size, abfd) != size)
    {
      free (buf);
      return FALSE;
    }

  memset (h, 0, sizeof (h));
  nsyms_found = 0;
  found_cap = 16;
  found_syms = (struct p9sym_entry *) bfd_malloc (
    found_cap * sizeof (struct p9sym_entry));
  if (found_syms == NULL)
    {
      free (buf);
      return FALSE;
    }

  /* Initial strtab (will grow) */
  strtab_size = 256;
  strtab = (char *) bfd_malloc (strtab_size);
  if (strtab == NULL)
    {
      free (found_syms);
      free (buf);
      return FALSE;
    }
  strtab_used = 0;

  pos = 0;
  while (pos + 2 <= size)
    {
      unsigned int opcode;
      int sym_idx, from_sz, to_sz;
      bfd_size_type rem;

      opcode = (unsigned int) buf[pos] | ((unsigned int) buf[pos + 1] << 8);
      rem = size - pos;

      if (opcode == P9OBJ_ANAME || opcode == P9OBJ_ASIGNAME)
        {
          /* ANAME: [2 opcode][1 type][1 sym][name...NUL]
             ASIGNAME: [2 opcode][4 sig][1 type][1 sym][name...NUL]  */
          bfd_size_type hdr_off;
          unsigned int dtype, sidx;
          const char *name;
          bfd_size_type name_start;
          unsigned char *nul;
          bfd_size_type namelen;

          if (opcode == P9OBJ_ASIGNAME)
            hdr_off = 2 + 4;  /* skip signature */
          else
            hdr_off = 2;

          if (pos + hdr_off + 2 > size)
            break;  /* truncated */

          dtype = buf[pos + hdr_off];
          sidx  = buf[pos + hdr_off + 1];
          name_start = pos + hdr_off + 2;

          if (name_start >= size)
            break;

          nul = (unsigned char *) memchr (buf + name_start, 0,
                                          size - name_start);
          if (nul == NULL)
            break;  /* no NUL terminator */

          namelen = (bfd_size_type)(nul - (buf + name_start));
          name = (const char *)(buf + name_start);

          /* Advance past this record */
          pos = (bfd_size_type)(nul - buf) + 1;

          /* Register non-file-history symbols (D_EXTERN / D_STATIC) */
          if ((dtype == P9OBJ_D_EXTERN || dtype == P9OBJ_D_STATIC)
              && sidx < 256 && namelen > 0
              && namelen < P9OBJ_MAX_NAMELEN)
            {
              /* Store name in strtab */
              bfd_size_type needed = strtab_used + namelen + 1;
              if (needed > strtab_size)
                {
                  char *newst;
                  while (strtab_size < needed)
                    strtab_size *= 2;
                  newst = (char *) bfd_realloc (strtab, strtab_size);
                  if (newst == NULL)
                    goto out_err;
                  strtab = newst;
                }
              memcpy (strtab + strtab_used, name, namelen + 1);

              h[sidx].dtype   = dtype;
              h[sidx].idx     = sidx;
              h[sidx].name    = strtab + strtab_used;
              h[sidx].section = bfd_und_section_ptr;
              h[sidx].value   = 0;

              strtab_used += namelen + 1;

              /* For D_EXTERN symbols, deduplicate by name: a single external
                 symbol can appear under multiple slot indices within one .8
                 file (e.g. both ADATA and AGLOBL reference the same global via
                 different ANAME slots).  Only add the first occurrence to avoid
                 "multiple definition" errors from the linker.  */
              if (dtype == P9OBJ_D_EXTERN)
                {
                  unsigned int prev_idx;
                  for (prev_idx = 0; prev_idx < nsyms_found; prev_idx++)
                    if (found_syms[prev_idx].dtype == P9OBJ_D_EXTERN
                        && found_syms[prev_idx].name != NULL
                        && strcmp (found_syms[prev_idx].name, name) == 0)
                      goto skip_add_extern;
                }

              /* Add to found_syms list */
              if (nsyms_found >= found_cap)
                {
                  struct p9sym_entry *newf;
                  found_cap *= 2;
                  newf = (struct p9sym_entry *) bfd_realloc (
                    found_syms, found_cap * sizeof (struct p9sym_entry));
                  if (newf == NULL)
                    goto out_err;
                  found_syms = newf;
                }
              found_syms[nsyms_found++] = h[sidx];
            skip_add_extern:;
            }
          else if ((dtype == P9OBJ_D_FILE || dtype == P9OBJ_D_FILE1)
                   && sidx < 256)
            {
              /* File history symbol - track but don't export */
              h[sidx].dtype   = dtype;
              h[sidx].idx     = sidx;
              h[sidx].name    = NULL;
              h[sidx].section = NULL;
              h[sidx].value   = 0;
            }
          continue;
        }

      /* All other records: [2-byte opcode][4-byte line][from_zaddr][to_zaddr] */
      if (rem < 2 + 4)
        break;

      from_sz = p9obj_zaddr_size (buf + pos + 6, rem - 6);
      if (from_sz < 0)
        break;
      to_sz = p9obj_zaddr_size (buf + pos + 6 + from_sz,
                                 rem - 6 - (bfd_size_type) from_sz);
      if (to_sz < 0)
        break;

      /* For ATEXT / ADATA / AGLOBL: update the section of referenced symbols */
      sym_idx = p9obj_zaddr_symidx (buf + pos + 6, rem - 6);
      if (sym_idx >= 0 && (unsigned int) sym_idx < 256
          && h[sym_idx].name != NULL)
        {
          unsigned int i2;
          asection *newsec = NULL;

          if (opcode == P9OBJ_ATEXT)
            newsec = bfd_get_section_by_name (abfd, ".text");
          else if (opcode == P9OBJ_ADATA)
            newsec = bfd_get_section_by_name (abfd, ".data");
          else if (opcode == P9OBJ_AGLOBL)
            newsec = bfd_get_section_by_name (abfd, ".bss");

          if (newsec != NULL)
            {
              /* Update section in found_syms for this symbol.
                 Search by name via h[] because after D_EXTERN deduplication
                 the found_syms entry may have a different slot index than the
                 one used in the current instruction record.  */
              const char *symname = h[sym_idx].name;
              for (i2 = 0; i2 < nsyms_found; i2++)
                {
                  if (found_syms[i2].name != NULL
                      && strcmp (found_syms[i2].name, symname) == 0)
                    {
                      found_syms[i2].section = newsec;
                      break;
                    }
                }
            }
        }

      pos += (bfd_size_type)(2 + 4 + from_sz + to_sz);
    }

  free (buf);
  buf = NULL;

  /* Build the asymbol array */
  if (nsyms_found > 0)
    {
      asymbol *syms = (asymbol *) bfd_malloc (
        nsyms_found * sizeof (asymbol));
      if (syms == NULL)
        goto out_err;

      for (i = 0; i < nsyms_found; i++)
        {
          syms[i].the_bfd = abfd;
          syms[i].name    = found_syms[i].name;
          syms[i].value   = found_syms[i].value;
          syms[i].section = found_syms[i].section;
          syms[i].udata.i = 0;

          if (found_syms[i].dtype == P9OBJ_D_EXTERN)
            syms[i].flags = BSF_GLOBAL;
          else
            syms[i].flags = BSF_LOCAL;

          /* If section is undefined (we never saw ATEXT/ADATA/AGLOBL for it),
             the symbol is an undefined external reference.  BSF_GLOBAL with
             bfd_und_section_ptr is the correct representation; BSF_WEAK is
             not appropriate here.  */
          if (found_syms[i].section == bfd_und_section_ptr)
            syms[i].flags = BSF_GLOBAL;  /* undefined external reference */
        }

      { asymbol **ptrs = (asymbol **) bfd_malloc (
                            nsyms_found * sizeof (asymbol *));
        if (ptrs)
          {
            unsigned int _j;
            for (_j = 0; _j < nsyms_found; _j++)
              ptrs[_j] = &syms[_j];
          }
        tdata->sym_ptrs = ptrs; }
      tdata->symbols  = syms;
      tdata->strtab   = strtab;
      tdata->strtab_len = strtab_used;
    }
  else
    {
      free (strtab);
      tdata->strtab = NULL;
    }

  tdata->nsyms = nsyms_found;
  bfd_get_symcount (abfd) = nsyms_found;
  free (found_syms);
  return TRUE;

out_err:
  if (buf)    free (buf);
  if (strtab) free (strtab);
  if (found_syms) free (found_syms);
  return FALSE;
}

/* --------------------------------------------------------------------- */
/* BFD entry points                                                        */

/* ================================================================
 * Phase 2: Plan 9 i386 instruction encoder
 * Implements the equivalent of 9front 8l span.c/optab.c inside BFD
 * so that .8 object files contribute real machine code when linked.
 * ================================================================ */

/* ---- Complete opcode values from 9front sys/src/cmd/8c/8.out.h --- */
/* (Only defines not already set above; grouped for clarity.)         */
/* Already defined: P9OBJ_ANAME=126, P9OBJ_ADATA=45, P9OBJ_AGLOBL=53 */
/* P9OBJ_AHISTORY=55, P9OBJ_ATEXT=220, P9OBJ_AEND=329, P9OBJ_ASIGNAME=332 */

#define P9AS_XXX        0
#define P9AS_AAA        1
#define P9AS_AAD        2
#define P9AS_AAM        3
#define P9AS_AAS        4
#define P9AS_ADCB       5
#define P9AS_ADCL       6
#define P9AS_ADCW       7
#define P9AS_ADDB       8
#define P9AS_ADDL       9
#define P9AS_ADDW       10
#define P9AS_ADJSP      11
#define P9AS_ANDB       12
#define P9AS_ANDL       13
#define P9AS_ANDW       14
#define P9AS_ARPL       15
#define P9AS_BOUNDL     16
#define P9AS_BOUNDW     17
#define P9AS_BSFL       18
#define P9AS_BSFW       19
#define P9AS_BSRL       20
#define P9AS_BSRW       21
#define P9AS_BTL        22
#define P9AS_BTW        23
#define P9AS_BTCL       24
#define P9AS_BTCW       25
#define P9AS_BTRL       26
#define P9AS_BTRW       27
#define P9AS_BTSL       28
#define P9AS_BTSW       29
#define P9AS_BYTE       30
#define P9AS_CALL       31
#define P9AS_CLC        32
#define P9AS_CLD        33
#define P9AS_CLI        34
#define P9AS_CLTS       35
#define P9AS_CMC        36
#define P9AS_CMPB       37
#define P9AS_CMPL       38
#define P9AS_CMPW       39
#define P9AS_CMPSB      40
#define P9AS_CMPSL      41
#define P9AS_CMPSW      42
#define P9AS_DAA        43
#define P9AS_DAS        44
#define P9AS_DATA       45
#define P9AS_DECB       46
#define P9AS_DECL       47
#define P9AS_DECW       48
#define P9AS_DIVB       49
#define P9AS_DIVL       50
#define P9AS_DIVW       51
#define P9AS_ENTER      52
#define P9AS_GLOBL      53
#define P9AS_GOK        54
#define P9AS_HISTORY    55
#define P9AS_HLT        56
#define P9AS_IDIVB      57
#define P9AS_IDIVL      58
#define P9AS_IDIVW      59
#define P9AS_IMULB      60
#define P9AS_IMULL      61
#define P9AS_IMULW      62
#define P9AS_INB        63
#define P9AS_INL        64
#define P9AS_INW        65
#define P9AS_INCB       66
#define P9AS_INCL       67
#define P9AS_INCW       68
#define P9AS_INSB       69
#define P9AS_INSL       70
#define P9AS_INSW       71
#define P9AS_INT        72
#define P9AS_INTO       73
#define P9AS_IRETL      74
#define P9AS_IRETW      75
#define P9AS_JCC        76
#define P9AS_JCS        77
#define P9AS_JCXZ       78
#define P9AS_JEQ        79
#define P9AS_JGE        80
#define P9AS_JGT        81
#define P9AS_JHI        82
#define P9AS_JLE        83
#define P9AS_JLS        84
#define P9AS_JLT        85
#define P9AS_JMI        86
#define P9AS_JMP        87
#define P9AS_JNE        88
#define P9AS_JOC        89
#define P9AS_JOS        90
#define P9AS_JPC        91
#define P9AS_JPL        92
#define P9AS_JPS        93
#define P9AS_LAHF       94
#define P9AS_LARL       95
#define P9AS_LARW       96
#define P9AS_LEAL       97
#define P9AS_LEAW       98
#define P9AS_LEAVEL     99
#define P9AS_LEAVEW     100
#define P9AS_LOCK       101
#define P9AS_LODSB      102
#define P9AS_LODSL      103
#define P9AS_LODSW      104
#define P9AS_LONG       105
#define P9AS_LOOP       106
#define P9AS_LOOPEQ     107
#define P9AS_LOOPNE     108
#define P9AS_LSLL       109
#define P9AS_LSLW       110
#define P9AS_MOVB       111
#define P9AS_MOVL       112
#define P9AS_MOVW       113
#define P9AS_MOVBLSX    114
#define P9AS_MOVBLZX    115
#define P9AS_MOVBWSX    116
#define P9AS_MOVBWZX    117
#define P9AS_MOVWLSX    118
#define P9AS_MOVWLZX    119
#define P9AS_MOVSB      120
#define P9AS_MOVSL      121
#define P9AS_MOVSW      122
#define P9AS_MULB       123
#define P9AS_MULL       124
#define P9AS_MULW       125
#define P9AS_NAME       126
#define P9AS_NEGB       127
#define P9AS_NEGL       128
#define P9AS_NEGW       129
#define P9AS_NOP        130
#define P9AS_NOTB       131
#define P9AS_NOTL       132
#define P9AS_NOTW       133
#define P9AS_ORB        134
#define P9AS_ORL        135
#define P9AS_ORW        136
#define P9AS_OUTB       137
#define P9AS_OUTL       138
#define P9AS_OUTW       139
#define P9AS_OUTSB      140
#define P9AS_OUTSL      141
#define P9AS_OUTSW      142
#define P9AS_POPAL      143
#define P9AS_POPAW      144
#define P9AS_POPFL      145
#define P9AS_POPFW      146
#define P9AS_POPL       147
#define P9AS_POPW       148
#define P9AS_PUSHAL     149
#define P9AS_PUSHAW     150
#define P9AS_PUSHFL     151
#define P9AS_PUSHFW     152
#define P9AS_PUSHL      153
#define P9AS_PUSHW      154
#define P9AS_RCLB       155
#define P9AS_RCLL       156
#define P9AS_RCLW       157
#define P9AS_RCRB       158
#define P9AS_RCRL       159
#define P9AS_RCRW       160
#define P9AS_REP        161
#define P9AS_REPN       162
#define P9AS_RET        163
#define P9AS_ROLB       164
#define P9AS_ROLL       165
#define P9AS_ROLW       166
#define P9AS_RORB       167
#define P9AS_RORL       168
#define P9AS_RORW       169
#define P9AS_SAHF       170
#define P9AS_SALB       171
#define P9AS_SALL       172
#define P9AS_SALW       173
#define P9AS_SARB       174
#define P9AS_SARL       175
#define P9AS_SARW       176
#define P9AS_SBBB       177
#define P9AS_SBBL       178
#define P9AS_SBBW       179
#define P9AS_SCASB      180
#define P9AS_SCASL      181
#define P9AS_SCASW      182
#define P9AS_SETCC      183
#define P9AS_SETCS      184
#define P9AS_SETEQ      185
#define P9AS_SETGE      186
#define P9AS_SETGT      187
#define P9AS_SETHI      188
#define P9AS_SETLE      189
#define P9AS_SETLS      190
#define P9AS_SETLT      191
#define P9AS_SETMI      192
#define P9AS_SETNE      193
#define P9AS_SETOC      194
#define P9AS_SETOS      195
#define P9AS_SETPC      196
#define P9AS_SETPL      197
#define P9AS_SETPS      198
#define P9AS_CDQ        199
#define P9AS_CWD        200
#define P9AS_SHLB       201
#define P9AS_SHLL       202
#define P9AS_SHLW       203
#define P9AS_SHRB       204
#define P9AS_SHRL       205
#define P9AS_SHRW       206
#define P9AS_STC        207
#define P9AS_STD        208
#define P9AS_STI        209
#define P9AS_STOSB      210
#define P9AS_STOSL      211
#define P9AS_STOSW      212
#define P9AS_SUBB       213
#define P9AS_SUBL       214
#define P9AS_SUBW       215
#define P9AS_SYSCALL    216
#define P9AS_TESTB      217
#define P9AS_TESTL      218
#define P9AS_TESTW      219
#define P9AS_TEXT       220
#define P9AS_VERR       221
#define P9AS_VERW       222
#define P9AS_WAIT       223
#define P9AS_WORD       224
#define P9AS_XCHGB      225
#define P9AS_XCHGL      226
#define P9AS_XCHGW      227
#define P9AS_XLAT       228
#define P9AS_XORB       229
#define P9AS_XORL       230
#define P9AS_XORW       231
/* FP opcodes 232..328 omitted (not needed for startup/libc) */
#define P9AS_END        329
#define P9AS_DYNT       330
#define P9AS_INIT       331
#define P9AS_SIGNAME    332
#define P9AS_LAST       380   /* upper bound for optab array */

/* D_* address types (8.out.h) */
#define P9D_AL    0
#define P9D_CL    1
#define P9D_DL    2
#define P9D_BL    3
#define P9D_AH    4
#define P9D_CH    5
#define P9D_DH    6
#define P9D_BH    7
#define P9D_AX    8
#define P9D_CX    9
#define P9D_DX    10
#define P9D_BX    11
#define P9D_SP    12
#define P9D_BP    13
#define P9D_SI    14
#define P9D_DI    15
#define P9D_F0    16
#define P9D_CS    24
#define P9D_SS    25
#define P9D_DS    26
#define P9D_ES    27
#define P9D_FS    28
#define P9D_GS    29
#define P9D_GDTR  30
#define P9D_IDTR  31
#define P9D_LDTR  32
#define P9D_MSW   33
#define P9D_TASK  34
#define P9D_CR    35
#define P9D_DR    43
#define P9D_TR    51
#define P9D_NONE  59
#define P9D_BRANCH 60
/* Already defined: P9OBJ_D_EXTERN=61, P9OBJ_D_STATIC=62 */
#define P9D_EXTERN 61
#define P9D_STATIC 62
#define P9D_AUTO   63
#define P9D_PARAM  64
#define P9D_CONST  65
#define P9D_FCONST 66
#define P9D_SCONST 67
#define P9D_ADDR   68
#define P9D_FILE   69
#define P9D_FILE1  70
#define P9D_INDIR  71   /* additive – P9D_INDIR+P9D_AX = mem[AX] etc. */
#define P9D_CONST2 (P9D_INDIR + P9D_INDIR)  /* = 142 */

/* Operand class codes (Yxxx) */
#define Yxxx   0
#define Ynone  1
#define Yi0    2
#define Yi1    3
#define Yi8    4
#define Yi32   5
#define Yiauto 6
#define Yal    7
#define Ycl    8
#define Yax    9
#define Ycx    10
#define Yrb    11
#define Yrl    12
#define Yrf    13
#define Yf0    14
#define Yrx    15
#define Ymb    16
#define Yml    17
#define Ym     18
#define Ybr    19
#define Ycol   20
#define Ycs    21
#define Yss    22
#define Yds    23
#define Yes    24
#define Yfs    25
#define Ygs    26
#define Ygdtr  27
#define Yidtr  28
#define Yldtr  29
#define Ymsw   30
#define Ytask  31
#define Ycr0   32
#define Ycr1   33
#define Ycr2   34
#define Ycr3   35
#define Ycr4   36
#define Ycr5   37
#define Ycr6   38
#define Ycr7   39
#define Ydr0   40
#define Ydr1   41
#define Ydr2   42
#define Ydr3   43
#define Ydr4   44
#define Ydr5   45
#define Ydr6   46
#define Ydr7   47
#define Ytr0   48
#define Ytr1   49
#define Ytr2   50
#define Ytr3   51
#define Ytr4   52
#define Ytr5   53
#define Ytr6   54
#define Ytr7   55
#define Ymax   56

/* Encoding action codes (Zxxx) */
#define Zxxx   0
#define Zlit   1
#define Z_rp   2
#define Zbr    3
#define Zcall  4
#define Zib_   5
#define Zib_rp 6
#define Zibo_m 7
#define Zil_   8
#define Zil_rp 9
#define Zilo_m 10
#define Zjmp   11
#define Zloop  12
#define Zm_o   13
#define Zm_r   14
#define Zaut_r 15
#define Zo_m   16
#define Zpseudo 17
#define Zr_m   18
#define Zrp_   19
#define Z_ib   20
#define Z_il   21
#define Zm_ibo 22
#define Zm_ilo 23
#define Zib_rr 24
#define Zil_rr 25
#define Zclr   26
#define Zbyte  27
#define Zmov   28
#define Zmax   29

/* Prefix codes */
#define Px  0x00   /* no prefix */
#define Pe  0x66   /* operand size escape */
#define Pm  0x0f   /* 2-byte opcode escape */
#define Pq  0xff   /* Pm then Pe (Pq = 0xff = both) */
#define Pb  0xfe   /* byte operands */

#define OE  0xff   /* end-of-opcode-list marker */

/* max instruction bytes we'll ever emit */
#define P9_MAXINSTR 30

/* ---- Instruction / address structures ----------------------------- */

typedef struct p9_Adr
{
  short  type;     /* D_xxx */
  short  index;    /* D_xxx (for SIB) */
  char   scale;    /* scale 1/2/4/8 */
  long   offset;   /* integer offset */
  int    sym;      /* index into sym table (-1 = none) */
  /* float/string constant storage (rarely used) */
  unsigned long fconst_l, fconst_h;
  char sconst[8];
} p9_Adr;

typedef struct p9_Prog
{
  short   as;          /* opcode */
  p9_Adr  from;
  p9_Adr  to;
  long    pc;          /* byte offset from text start */
  int     mark;        /* encoded size in bytes */
  int     back;        /* branch direction (2 = backward by default) */
  int     pcond_idx;   /* index of branch target in prog array (-1=none) */
} p9_Prog;

/* ---- Optab structure ---------------------------------------------- */

typedef struct p9_Optab
{
  short   as;
  const unsigned char *ytab;
  unsigned char prefix;
  unsigned char op[10];
} p9_Optab;

/* ---- ytab data (operand-class dispatch tables) -------------------- */
/* Each entry is 4 bytes: from_class, to_class, action, arg */

static const unsigned char p9_ynone[] = { Ynone,Ynone,Zlit,1,  0 };
static const unsigned char p9_ytext[] = { Ymb,Yi32,Zpseudo,1,  0 };
static const unsigned char p9_ynop[]  = {
  Ynone,Ynone,Zpseudo,1,
  Ynone,Yml, Zpseudo,1,
  Ynone,Yrf, Zpseudo,1,
  Yml,  Ynone,Zpseudo,1,
  Yrf,  Ynone,Zpseudo,1,
  0
};
static const unsigned char p9_yxorb[] = {
  Yi32,Yal,Zib_,1,
  Yi32,Ymb,Zibo_m,2,
  Yrb, Ymb,Zr_m,1,
  Ymb, Yrb,Zm_r,1,
  0
};
static const unsigned char p9_yxorl[] = {
  Yi8, Yml,Zibo_m,2,
  Yi32,Yax,Zil_,1,
  Yi32,Yml,Zilo_m,2,
  Yrl, Yml,Zr_m,1,
  Yml, Yrl,Zm_r,1,
  0
};
static const unsigned char p9_yaddl[] = {
  Yi8, Yml,Zibo_m,2,
  Yi32,Yax,Zil_,1,
  Yi32,Yml,Zilo_m,2,
  Yrl, Yml,Zr_m,1,
  Yml, Yrl,Zm_r,1,
  0
};
static const unsigned char p9_yincb[] = { Ynone,Ymb,Zo_m,2,  0 };
static const unsigned char p9_yincl[] = { Ynone,Yrl,Z_rp,1, Ynone,Yml,Zo_m,2, 0 };
static const unsigned char p9_ycmpb[] = {
  Yal,Yi32,Z_ib,1,
  Ymb,Yi32,Zm_ibo,2,
  Ymb,Yrb, Zm_r,1,
  Yrb,Ymb, Zr_m,1,
  0
};
static const unsigned char p9_ycmpl[] = {
  Yml,Yi8, Zm_ibo,2,
  Yax,Yi32,Z_il,1,
  Yml,Yi32,Zm_ilo,2,
  Yml,Yrl, Zm_r,1,
  Yrl,Yml, Zr_m,1,
  0
};
static const unsigned char p9_yshb[] = {
  Yi0+1,Ymb,Zo_m,2,
  Yi8,  Ymb,Zibo_m,2,
  Ycx,  Ymb,Zo_m,2,
  0
};
static const unsigned char p9_yshl[] = {
  Yi0+1,Yml,Zo_m,2,
  Yi8,  Yml,Zibo_m,2,
  Ycl,  Yml,Zo_m,2,
  Ycx,  Yml,Zo_m,2,
  0
};
static const unsigned char p9_ytestb[] = {
  Yi32,Yal,Zib_,1,
  Yi32,Ymb,Zibo_m,2,
  Yrb, Ymb,Zr_m,1,
  Ymb, Yrb,Zm_r,1,
  0
};
static const unsigned char p9_ytestl[] = {
  Yi32,Yax,Zil_,1,
  Yi32,Yml,Zilo_m,2,
  Yrl, Yml,Zr_m,1,
  Yml, Yrl,Zm_r,1,
  0
};
static const unsigned char p9_ymovb[] = {
  Yrb, Ymb,Zr_m,1,
  Ymb, Yrb,Zm_r,1,
  Yi32,Yrb,Zib_rp,1,
  Yi32,Ymb,Zibo_m,2,
  0
};
static const unsigned char p9_ymovl[] = {
  Yrl, Yml,Zr_m,1,
  Yml, Yrl,Zm_r,1,
  Yi0, Yrl,Zclr,3,
  Yi32,Yrl,Zil_rp,1,
  Yi32,Yml,Zilo_m,2,
  Yiauto,Yrl,Zaut_r,2,
  0
};
static const unsigned char p9_ym_rl[]  = { Ym,  Yrl,Zm_r,1, 0 };
static const unsigned char p9_ymb_rl[] = { Ymb, Yrl,Zm_r,1, 0 };
static const unsigned char p9_yml_rl[] = { Yml, Yrl,Zm_r,1, 0 };
static const unsigned char p9_yml_mb[] = { Yrb,Ymb,Zr_m,1, Ymb,Yrb,Zm_r,1, 0 };
static const unsigned char p9_yml_ml[] = { Yrl,Yml,Zr_m,1, Yml,Yrl,Zm_r,1, 0 };
static const unsigned char p9_ydivl[]  = { Yml,Ynone,Zm_o,2, 0 };
static const unsigned char p9_ydivb[]  = { Ymb,Ynone,Zm_o,2, 0 };
static const unsigned char p9_yimul[]  = {
  Yml,Ynone,Zm_o,2,
  Yi8, Yrl,Zib_rr,1,
  Yi32,Yrl,Zil_rr,1,
  0
};
static const unsigned char p9_ybyte[]  = { Yi32,Ynone,Zbyte,1, 0 };
static const unsigned char p9_yin[]    = { Yi32,Ynone,Zib_,1, Ynone,Ynone,Zlit,1, 0 };
static const unsigned char p9_yint[]   = { Yi32,Ynone,Zib_,1, 0 };
static const unsigned char p9_ypushl[] = {
  Yrl, Ynone,Zrp_,1,
  Ym,  Ynone,Zm_o,2,
  Yi8, Ynone,Zib_,1,
  Yi32,Ynone,Zil_,1,
  0
};
static const unsigned char p9_ypopl[]  = { Ynone,Yrl,Z_rp,1, Ynone,Ym,Zo_m,2, 0 };
static const unsigned char p9_yscond[] = { Ynone,Ymb,Zo_m,2, 0 };
static const unsigned char p9_yjcond[] = { Ynone,Ybr,Zbr,1, 0 };
static const unsigned char p9_yloop[]  = { Ynone,Ybr,Zloop,1, 0 };
static const unsigned char p9_ycall[]  = { Ynone,Yml,Zo_m,2, Ynone,Ybr,Zcall,1, 0 };
static const unsigned char p9_yjmp[]   = { Ynone,Yml,Zo_m,2, Ynone,Ybr,Zjmp,1, 0 };

/* ---- The optab array (indexed by opcode value) ------------------- */
/* Entries for opcodes we don't support are left zero (NULL ytab).   */

static p9_Optab p9_optab[P9AS_LAST + 1];

/* Yi1 is 3 in our mapping but the ytab uses Yi1 literally.
   We need a value for "Yi1" in the ytab that maps to Yi1 index = 3.
   But in p9_yshb we used Yi0+1 which equals 3 = Yi1.  Good. */

static void
p9_init_optab (void)
{
  /* Only initialize entries on first call */
  static int done = 0;
  if (done) return;
  done = 1;

/* Note: use 'opc' (not 'as') to avoid shadowing the '.as' struct field.
   Prepend a dummy 0 so ##__VA_ARGS__ works when the list is empty. */
#define O(opc, yt, pre, ...) do { \
  unsigned char _ops[] = {0, ##__VA_ARGS__}; \
  int _n = (int)sizeof(_ops) - 1; \
  p9_optab[(opc)].as = (short)(opc); \
  p9_optab[(opc)].ytab = (yt); \
  p9_optab[(opc)].prefix = (unsigned char)(pre); \
  { int _i; if (_n > 10) _n = 10; \
    for (_i = 0; _i < _n; _i++) p9_optab[(opc)].op[_i] = _ops[_i+1]; } \
} while(0)

  O(P9AS_AAA,    p9_ynone, Px, 0x37);
  O(P9AS_AAD,    p9_ynone, Px, 0xd5,0x0a);
  O(P9AS_AAM,    p9_ynone, Px, 0xd4,0x0a);
  O(P9AS_AAS,    p9_ynone, Px, 0x3f);
  O(P9AS_ADCB,   p9_yxorb, Pb, 0x14,0x80,0x02,0x10,0x10);
  O(P9AS_ADCL,   p9_yxorl, Px, 0x83,0x02,0x15,0x81,0x02,0x11,0x13);
  O(P9AS_ADCW,   p9_yxorl, Pe, 0x83,0x02,0x15,0x81,0x02,0x11,0x13);
  O(P9AS_ADDB,   p9_yxorb, Pb, 0x04,0x80,0x00,0x00,0x02);
  O(P9AS_ADDL,   p9_yaddl, Px, 0x83,0x00,0x05,0x81,0x00,0x01,0x03);
  O(P9AS_ADDW,   p9_yaddl, Pe, 0x83,0x00,0x05,0x81,0x00,0x01,0x03);
  O(P9AS_ANDB,   p9_yxorb, Pb, 0x24,0x80,0x04,0x20,0x22);
  O(P9AS_ANDL,   p9_yxorl, Px, 0x83,0x04,0x25,0x81,0x04,0x21,0x23);
  O(P9AS_ANDW,   p9_yxorl, Pe, 0x83,0x04,0x25,0x81,0x04,0x21,0x23);
  O(P9AS_BYTE,   p9_ybyte, Px, 1);
  O(P9AS_CALL,   p9_ycall, Px, 0xff,0x02,0xe8);
  O(P9AS_CLC,    p9_ynone, Px, 0xf8);
  O(P9AS_CLD,    p9_ynone, Px, 0xfc);
  O(P9AS_CLI,    p9_ynone, Px, 0xfa);
  O(P9AS_CLTS,   p9_ynone, Pm, 0x06);
  O(P9AS_CMC,    p9_ynone, Px, 0xf5);
  O(P9AS_CMPB,   p9_ycmpb, Pb, 0x3c,0x80,0x07,0x38,0x3a);
  O(P9AS_CMPL,   p9_ycmpl, Px, 0x83,0x07,0x3d,0x81,0x07,0x39,0x3b);
  O(P9AS_CMPW,   p9_ycmpl, Pe, 0x83,0x07,0x3d,0x81,0x07,0x39,0x3b);
  O(P9AS_CMPSB,  p9_ynone, Pb, 0xa6);
  O(P9AS_CMPSL,  p9_ynone, Px, 0xa7);
  O(P9AS_CMPSW,  p9_ynone, Pe, 0xa7);
  O(P9AS_DAA,    p9_ynone, Px, 0x27);
  O(P9AS_DAS,    p9_ynone, Px, 0x2f);
  O(P9AS_DECB,   p9_yincb, Pb, 0xfe,0x01);
  O(P9AS_DECL,   p9_yincl, Px, 0x48,0xff,0x01);
  O(P9AS_DECW,   p9_yincl, Pe, 0x48,0xff,0x01);
  O(P9AS_DIVB,   p9_ydivb, Pb, 0xf6,0x06);
  O(P9AS_DIVL,   p9_ydivl, Px, 0xf7,0x06);
  O(P9AS_DIVW,   p9_ydivl, Pe, 0xf7,0x06);
  O(P9AS_HLT,    p9_ynone, Px, 0xf4);
  O(P9AS_IDIVB,  p9_ydivb, Pb, 0xf6,0x07);
  O(P9AS_IDIVL,  p9_ydivl, Px, 0xf7,0x07);
  O(P9AS_IDIVW,  p9_ydivl, Pe, 0xf7,0x07);
  O(P9AS_IMULB,  p9_ydivb, Pb, 0xf6,0x05);
  O(P9AS_IMULL,  p9_yimul, Px, 0xf7,0x05,0x6b,0x69);
  O(P9AS_IMULW,  p9_yimul, Pe, 0xf7,0x05,0x6b,0x69);
  O(P9AS_INB,    p9_yin,   Pb, 0xe4,0xec);
  O(P9AS_INL,    p9_yin,   Px, 0xe5,0xed);
  O(P9AS_INW,    p9_yin,   Pe, 0xe5,0xed);
  O(P9AS_INCB,   p9_yincb, Pb, 0xfe,0x00);
  O(P9AS_INCL,   p9_yincl, Px, 0x40,0xff,0x00);
  O(P9AS_INCW,   p9_yincl, Pe, 0x40,0xff,0x00);
  O(P9AS_INSB,   p9_ynone, Pb, 0x6c);
  O(P9AS_INSL,   p9_ynone, Px, 0x6d);
  O(P9AS_INSW,   p9_ynone, Pe, 0x6d);
  O(P9AS_INT,    p9_yint,  Px, 0xcd);
  O(P9AS_INTO,   p9_ynone, Px, 0xce);
  O(P9AS_IRETL,  p9_ynone, Px, 0xcf);
  O(P9AS_IRETW,  p9_ynone, Pe, 0xcf);
  O(P9AS_JCC,    p9_yjcond,Px, 0x73,0x83,0x00);
  O(P9AS_JCS,    p9_yjcond,Px, 0x72,0x82);
  O(P9AS_JCXZ,   p9_yloop, Px, 0xe3);
  O(P9AS_JEQ,    p9_yjcond,Px, 0x74,0x84);
  O(P9AS_JGE,    p9_yjcond,Px, 0x7d,0x8d);
  O(P9AS_JGT,    p9_yjcond,Px, 0x7f,0x8f);
  O(P9AS_JHI,    p9_yjcond,Px, 0x77,0x87);
  O(P9AS_JLE,    p9_yjcond,Px, 0x7e,0x8e);
  O(P9AS_JLS,    p9_yjcond,Px, 0x76,0x86);
  O(P9AS_JLT,    p9_yjcond,Px, 0x7c,0x8c);
  O(P9AS_JMI,    p9_yjcond,Px, 0x78,0x88);
  O(P9AS_JMP,    p9_yjmp,  Px, 0xff,0x04,0xeb,0xe9);
  O(P9AS_JNE,    p9_yjcond,Px, 0x75,0x85);
  O(P9AS_JOC,    p9_yjcond,Px, 0x71,0x81,0x00);
  O(P9AS_JOS,    p9_yjcond,Px, 0x70,0x80,0x00);
  O(P9AS_JPC,    p9_yjcond,Px, 0x7b,0x8b);
  O(P9AS_JPL,    p9_yjcond,Px, 0x79,0x89);
  O(P9AS_JPS,    p9_yjcond,Px, 0x7a,0x8a);
  O(P9AS_LAHF,   p9_ynone, Px, 0x9f);
  O(P9AS_LARL,   p9_yml_rl,Pm, 0x02);
  O(P9AS_LARW,   p9_yml_rl,Pq, 0x02);
  O(P9AS_LEAL,   p9_ym_rl, Px, 0x8d);
  O(P9AS_LEAW,   p9_ym_rl, Pe, 0x8d);
  O(P9AS_LEAVEL, p9_ynone, Px, 0xc9);
  O(P9AS_LEAVEW, p9_ynone, Pe, 0xc9);
  O(P9AS_LOCK,   p9_ynone, Px, 0xf0);
  O(P9AS_LODSB,  p9_ynone, Pb, 0xac);
  O(P9AS_LODSL,  p9_ynone, Px, 0xad);
  O(P9AS_LODSW,  p9_ynone, Pe, 0xad);
  O(P9AS_LONG,   p9_ybyte, Px, 4);
  O(P9AS_LOOP,   p9_yloop, Px, 0xe2);
  O(P9AS_LOOPEQ, p9_yloop, Px, 0xe1);
  O(P9AS_LOOPNE, p9_yloop, Px, 0xe0);
  O(P9AS_LSLL,   p9_yml_rl,Pm, 0x03);
  O(P9AS_LSLW,   p9_yml_rl,Pq, 0x03);
  O(P9AS_MOVB,   p9_ymovb, Pb, 0x88,0x8a,0xb0,0xc6,0x00);
  O(P9AS_MOVL,   p9_ymovl, Px, 0x89,0x8b,0x31,0x83,0x04,0xb8,0xc7,0x00);
  O(P9AS_MOVW,   p9_ymovl, Pe, 0x89,0x8b,0x31,0x83,0x04,0xb8,0xc7,0x00);
  O(P9AS_MOVBLSX,p9_ymb_rl,Pm, 0xbe);
  O(P9AS_MOVBLZX,p9_ymb_rl,Pm, 0xb6);
  O(P9AS_MOVBWSX,p9_ymb_rl,Pq, 0xbe);
  O(P9AS_MOVBWZX,p9_ymb_rl,Pq, 0xb6);
  O(P9AS_MOVWLSX,p9_yml_rl,Pm, 0xbf);
  O(P9AS_MOVWLZX,p9_yml_rl,Pm, 0xb7);
  O(P9AS_MOVSB,  p9_ynone, Pb, 0xa4);
  O(P9AS_MOVSL,  p9_ynone, Px, 0xa5);
  O(P9AS_MOVSW,  p9_ynone, Pe, 0xa5);
  O(P9AS_MULB,   p9_ydivb, Pb, 0xf6,0x04);
  O(P9AS_MULL,   p9_ydivl, Px, 0xf7,0x04);
  O(P9AS_MULW,   p9_ydivl, Pe, 0xf7,0x04);
  O(P9AS_NEGB,   p9_yscond,Px, 0xf6,0x03);
  O(P9AS_NEGL,   p9_yscond,Px, 0xf7,0x03);
  O(P9AS_NEGW,   p9_yscond,Pe, 0xf7,0x03);
  O(P9AS_NOP,    p9_ynop,  Px, 0,0);
  O(P9AS_NOTB,   p9_yscond,Px, 0xf6,0x02);
  O(P9AS_NOTL,   p9_yscond,Px, 0xf7,0x02);
  O(P9AS_NOTW,   p9_yscond,Pe, 0xf7,0x02);
  O(P9AS_ORB,    p9_yxorb, Pb, 0x0c,0x80,0x01,0x08,0x0a);
  O(P9AS_ORL,    p9_yxorl, Px, 0x83,0x01,0x0d,0x81,0x01,0x09,0x0b);
  O(P9AS_ORW,    p9_yxorl, Pe, 0x83,0x01,0x0d,0x81,0x01,0x09,0x0b);
  O(P9AS_OUTB,   p9_yin,   Pb, 0xe6,0xee);
  O(P9AS_OUTL,   p9_yin,   Px, 0xe7,0xef);
  O(P9AS_OUTW,   p9_yin,   Pe, 0xe7,0xef);
  O(P9AS_OUTSB,  p9_ynone, Pb, 0x6e);
  O(P9AS_OUTSL,  p9_ynone, Px, 0x6f);
  O(P9AS_OUTSW,  p9_ynone, Pe, 0x6f);
  O(P9AS_POPAL,  p9_ynone, Px, 0x61);
  O(P9AS_POPAW,  p9_ynone, Pe, 0x61);
  O(P9AS_POPFL,  p9_ynone, Px, 0x9d);
  O(P9AS_POPFW,  p9_ynone, Pe, 0x9d);
  O(P9AS_POPL,   p9_ypopl, Px, 0x58,0x8f,0x00);
  O(P9AS_POPW,   p9_ypopl, Pe, 0x58,0x8f,0x00);
  O(P9AS_PUSHAL, p9_ynone, Px, 0x60);
  O(P9AS_PUSHAW, p9_ynone, Pe, 0x60);
  O(P9AS_PUSHFL, p9_ynone, Px, 0x9c);
  O(P9AS_PUSHFW, p9_ynone, Pe, 0x9c);
  O(P9AS_PUSHL,  p9_ypushl,Px, 0x50,0xff,0x06,0x6a,0x68);
  O(P9AS_PUSHW,  p9_ypushl,Pe, 0x50,0xff,0x06,0x6a,0x68);
  O(P9AS_RCLB,   p9_yshb,  Pb, 0xd0,0x02,0xc0,0x02,0xd2,0x02);
  O(P9AS_RCLL,   p9_yshl,  Px, 0xd1,0x02,0xc1,0x02,0xd3,0x02,0xd3,0x02);
  O(P9AS_RCLW,   p9_yshl,  Pe, 0xd1,0x02,0xc1,0x02,0xd3,0x02,0xd3,0x02);
  O(P9AS_RCRB,   p9_yshb,  Pb, 0xd0,0x03,0xc0,0x03,0xd2,0x03);
  O(P9AS_RCRL,   p9_yshl,  Px, 0xd1,0x03,0xc1,0x03,0xd3,0x03,0xd3,0x03);
  O(P9AS_RCRW,   p9_yshl,  Pe, 0xd1,0x03,0xc1,0x03,0xd3,0x03,0xd3,0x03);
  O(P9AS_REP,    p9_ynone, Px, 0xf3);
  O(P9AS_REPN,   p9_ynone, Px, 0xf2);
  O(P9AS_RET,    p9_ynone, Px, 0xc3);
  O(P9AS_ROLB,   p9_yshb,  Pb, 0xd0,0x00,0xc0,0x00,0xd2,0x00);
  O(P9AS_ROLL,   p9_yshl,  Px, 0xd1,0x00,0xc1,0x00,0xd3,0x00,0xd3,0x00);
  O(P9AS_ROLW,   p9_yshl,  Pe, 0xd1,0x00,0xc1,0x00,0xd3,0x00,0xd3,0x00);
  O(P9AS_RORB,   p9_yshb,  Pb, 0xd0,0x01,0xc0,0x01,0xd2,0x01);
  O(P9AS_RORL,   p9_yshl,  Px, 0xd1,0x01,0xc1,0x01,0xd3,0x01,0xd3,0x01);
  O(P9AS_RORW,   p9_yshl,  Pe, 0xd1,0x01,0xc1,0x01,0xd3,0x01,0xd3,0x01);
  O(P9AS_SAHF,   p9_ynone, Px, 0x9e);
  O(P9AS_SALB,   p9_yshb,  Pb, 0xd0,0x04,0xc0,0x04,0xd2,0x04);
  O(P9AS_SALL,   p9_yshl,  Px, 0xd1,0x04,0xc1,0x04,0xd3,0x04,0xd3,0x04);
  O(P9AS_SALW,   p9_yshl,  Pe, 0xd1,0x04,0xc1,0x04,0xd3,0x04,0xd3,0x04);
  O(P9AS_SARB,   p9_yshb,  Pb, 0xd0,0x07,0xc0,0x07,0xd2,0x07);
  O(P9AS_SARL,   p9_yshl,  Px, 0xd1,0x07,0xc1,0x07,0xd3,0x07,0xd3,0x07);
  O(P9AS_SARW,   p9_yshl,  Pe, 0xd1,0x07,0xc1,0x07,0xd3,0x07,0xd3,0x07);
  O(P9AS_SBBB,   p9_yxorb, Pb, 0x1c,0x80,0x03,0x18,0x1a);
  O(P9AS_SBBL,   p9_yxorl, Px, 0x83,0x03,0x1d,0x81,0x03,0x19,0x1b);
  O(P9AS_SBBW,   p9_yxorl, Pe, 0x83,0x03,0x1d,0x81,0x03,0x19,0x1b);
  O(P9AS_SCASB,  p9_ynone, Pb, 0xae);
  O(P9AS_SCASL,  p9_ynone, Px, 0xaf);
  O(P9AS_SCASW,  p9_ynone, Pe, 0xaf);
  O(P9AS_SETCC,  p9_yscond,Pm, 0x93,0x00);
  O(P9AS_SETCS,  p9_yscond,Pm, 0x92,0x00);
  O(P9AS_SETEQ,  p9_yscond,Pm, 0x94,0x00);
  O(P9AS_SETGE,  p9_yscond,Pm, 0x9d,0x00);
  O(P9AS_SETGT,  p9_yscond,Pm, 0x9f,0x00);
  O(P9AS_SETHI,  p9_yscond,Pm, 0x97,0x00);
  O(P9AS_SETLE,  p9_yscond,Pm, 0x9e,0x00);
  O(P9AS_SETLS,  p9_yscond,Pm, 0x96,0x00);
  O(P9AS_SETLT,  p9_yscond,Pm, 0x9c,0x00);
  O(P9AS_SETMI,  p9_yscond,Pm, 0x98,0x00);
  O(P9AS_SETNE,  p9_yscond,Pm, 0x95,0x00);
  O(P9AS_SETOC,  p9_yscond,Pm, 0x91,0x00);
  O(P9AS_SETOS,  p9_yscond,Pm, 0x90,0x00);
  O(P9AS_SETPC,  p9_yscond,Pm, 0x96,0x00);
  O(P9AS_SETPL,  p9_yscond,Pm, 0x99,0x00);
  O(P9AS_SETPS,  p9_yscond,Pm, 0x9a,0x00);
  O(P9AS_CDQ,    p9_ynone, Px, 0x99);
  O(P9AS_CWD,    p9_ynone, Pe, 0x99);
  O(P9AS_SHLB,   p9_yshb,  Pb, 0xd0,0x04,0xc0,0x04,0xd2,0x04);
  O(P9AS_SHLL,   p9_yshl,  Px, 0xd1,0x04,0xc1,0x04,0xd3,0x04,0xd3,0x04);
  O(P9AS_SHLW,   p9_yshl,  Pe, 0xd1,0x04,0xc1,0x04,0xd3,0x04,0xd3,0x04);
  O(P9AS_SHRB,   p9_yshb,  Pb, 0xd0,0x05,0xc0,0x05,0xd2,0x05);
  O(P9AS_SHRL,   p9_yshl,  Px, 0xd1,0x05,0xc1,0x05,0xd3,0x05,0xd3,0x05);
  O(P9AS_SHRW,   p9_yshl,  Pe, 0xd1,0x05,0xc1,0x05,0xd3,0x05,0xd3,0x05);
  O(P9AS_STC,    p9_ynone, Px, 0xf9);
  O(P9AS_STD,    p9_ynone, Px, 0xfd);
  O(P9AS_STI,    p9_ynone, Px, 0xfb);
  O(P9AS_STOSB,  p9_ynone, Pb, 0xaa);
  O(P9AS_STOSL,  p9_ynone, Px, 0xab);
  O(P9AS_STOSW,  p9_ynone, Pe, 0xab);
  O(P9AS_SUBB,   p9_yxorb, Pb, 0x2c,0x80,0x05,0x28,0x2a);
  O(P9AS_SUBL,   p9_yaddl, Px, 0x83,0x05,0x2d,0x81,0x05,0x29,0x2b);
  O(P9AS_SUBW,   p9_yaddl, Pe, 0x83,0x05,0x2d,0x81,0x05,0x29,0x2b);
  O(P9AS_SYSCALL,p9_ynone, Px, 0xcd,100);
  O(P9AS_TESTB,  p9_ytestb,Pb, 0xa8,0xf6,0x00,0x84,0x84);
  O(P9AS_TESTL,  p9_ytestl,Px, 0xa9,0xf7,0x00,0x85,0x85);
  O(P9AS_TESTW,  p9_ytestl,Pe, 0xa9,0xf7,0x00,0x85,0x85);
  O(P9AS_TEXT,   p9_ytext, Px);
  O(P9AS_VERR,   p9_ydivl, Pm, 0x00,0x04);
  O(P9AS_VERW,   p9_ydivl, Pm, 0x00,0x05);
  O(P9AS_WAIT,   p9_ynone, Px, 0x9b);
  O(P9AS_WORD,   p9_ybyte, Px, 2);
  O(P9AS_XCHGB,  p9_yml_mb,Pb, 0x86,0x86);
  O(P9AS_XCHGL,  p9_yml_ml,Px, 0x87,0x87);
  O(P9AS_XCHGW,  p9_yml_ml,Pe, 0x87,0x87);
  O(P9AS_XLAT,   p9_ynone, Px, 0xd7);
  O(P9AS_XORB,   p9_yxorb, Pb, 0x34,0x80,0x06,0x30,0x32);
  O(P9AS_XORL,   p9_yxorl, Px, 0x83,0x06,0x35,0x81,0x06,0x31,0x33);
  O(P9AS_XORW,   p9_yxorl, Pe, 0x83,0x06,0x35,0x81,0x06,0x31,0x33);
#undef O
}

/* ---- ymov special-case table (from 9front span.c ymovtab[]) ------ */
/* Each entry: opcode, from_class, to_class, action, op[0..3]         */
#define YMOV_E OE
static const unsigned char p9_ymovtab[] = {
  P9AS_PUSHL,Ycs,Ynone,0, 0x0e,YMOV_E,0,0,
  P9AS_PUSHL,Yss,Ynone,0, 0x16,YMOV_E,0,0,
  P9AS_PUSHL,Yds,Ynone,0, 0x1e,YMOV_E,0,0,
  P9AS_PUSHL,Yes,Ynone,0, 0x06,YMOV_E,0,0,
  P9AS_PUSHL,Yfs,Ynone,0, 0x0f,0xa0,YMOV_E,0,
  P9AS_PUSHL,Ygs,Ynone,0, 0x0f,0xa8,YMOV_E,0,
  P9AS_POPL, Ynone,Yds,0, 0x1f,YMOV_E,0,0,
  P9AS_POPL, Ynone,Yes,0, 0x07,YMOV_E,0,0,
  P9AS_POPL, Ynone,Yss,0, 0x17,YMOV_E,0,0,
  P9AS_POPL, Ynone,Yfs,0, 0x0f,0xa1,YMOV_E,0,
  P9AS_POPL, Ynone,Ygs,0, 0x0f,0xa9,YMOV_E,0,
  P9AS_MOVW, Yes,  Yml, 1, 0x8c,0,0,0,
  P9AS_MOVW, Ycs,  Yml, 1, 0x8c,1,0,0,
  P9AS_MOVW, Yss,  Yml, 1, 0x8c,2,0,0,
  P9AS_MOVW, Yds,  Yml, 1, 0x8c,3,0,0,
  P9AS_MOVW, Yfs,  Yml, 1, 0x8c,4,0,0,
  P9AS_MOVW, Ygs,  Yml, 1, 0x8c,5,0,0,
  P9AS_MOVW, Yml,  Yes, 2, 0x8e,0,0,0,
  P9AS_MOVW, Yml,  Ycs, 2, 0x8e,1,0,0,
  P9AS_MOVW, Yml,  Yss, 2, 0x8e,2,0,0,
  P9AS_MOVW, Yml,  Yds, 2, 0x8e,3,0,0,
  P9AS_MOVW, Yml,  Yfs, 2, 0x8e,4,0,0,
  P9AS_MOVW, Yml,  Ygs, 2, 0x8e,5,0,0,
  0
};

/* ---- ycover matrix (Ymax x Ymax) --------------------------------- */
static unsigned char p9_ycover[Ymax * Ymax];

/* reg[] map: D_AX..D_DI -> 0..7 */
static char p9_reg[P9D_NONE + 1];

static void
p9_init_tables (void)
{
  static int done = 0;
  int i;
  if (done) return;
  done = 1;

  /* ycover[a*Ymax + b] = 1 means class a satisfies class b */
  for (i = 0; i < Ymax; i++)
    p9_ycover[i * Ymax + i] = 1;   /* every class covers itself */

  p9_ycover[Yi0 * Ymax + Yi8]  = 1;
  p9_ycover[Yi1 * Ymax + Yi8]  = 1;   /* Yi1 also in note: Yi1 = 3 */
  p9_ycover[Yi0 * Ymax + Yi32] = 1;
  p9_ycover[Yi1 * Ymax + Yi32] = 1;
  p9_ycover[Yi8 * Ymax + Yi32] = 1;

  p9_ycover[Yal * Ymax + Yrb]  = 1;
  p9_ycover[Ycl * Ymax + Yrb]  = 1;
  p9_ycover[Yax * Ymax + Yrb]  = 1;
  p9_ycover[Ycx * Ymax + Yrb]  = 1;
  p9_ycover[Yrx * Ymax + Yrb]  = 1;

  p9_ycover[Yax * Ymax + Yrx]  = 1;
  p9_ycover[Ycx * Ymax + Yrx]  = 1;

  p9_ycover[Yax * Ymax + Yrl]  = 1;
  p9_ycover[Ycx * Ymax + Yrl]  = 1;
  p9_ycover[Yrx * Ymax + Yrl]  = 1;

  p9_ycover[Yf0 * Ymax + Yrf]  = 1;

  p9_ycover[Yal * Ymax + Ymb]  = 1;
  p9_ycover[Ycl * Ymax + Ymb]  = 1;
  p9_ycover[Yax * Ymax + Ymb]  = 1;
  p9_ycover[Ycx * Ymax + Ymb]  = 1;
  p9_ycover[Yrx * Ymax + Ymb]  = 1;
  p9_ycover[Yrb * Ymax + Ymb]  = 1;
  p9_ycover[Ym  * Ymax + Ymb]  = 1;

  p9_ycover[Yax * Ymax + Yml]  = 1;
  p9_ycover[Ycx * Ymax + Yml]  = 1;
  p9_ycover[Yrx * Ymax + Yml]  = 1;
  p9_ycover[Yrl * Ymax + Yml]  = 1;
  p9_ycover[Ym  * Ymax + Yml]  = 1;

  /* reg[] map */
  for (i = 0; i <= P9D_NONE; i++)
    p9_reg[i] = -1;
  for (i = P9D_AL; i <= (P9D_AL + 7); i++)
    p9_reg[i] = (i - P9D_AL) & 7;
  for (i = P9D_AX; i <= P9D_DI; i++)
    p9_reg[i] = (i - P9D_AX) & 7;
  for (i = P9D_F0; i <= P9D_F0 + 7; i++)
    p9_reg[i] = (i - P9D_F0) & 7;
}


/* ================================================================
 * Encoding context – passed through the encode pass.
 * ================================================================ */

typedef struct p9_EncCtx
{
  unsigned char  *andptr;          /* current write pointer */
  unsigned char   and_buf[P9_MAXINSTR]; /* per-instruction byte buffer */
  long            cur_pc;          /* current instruction PC */
  /* for reloc generation: filled in when put4() is called for extern */
  int             reloc_sym;       /* symbol index needing reloc, or -1 */
  long            reloc_offset;    /* offset in section */
  int             reloc_pcrel;     /* 1 = PC-relative, 0 = absolute */
  int             n_relocs;
  int             reloc_cap;
  /* deferred reloc list */
  int            *reloc_syms;
  long           *reloc_offsets;
  int            *reloc_pcrls;
} p9_EncCtx;

/* Symbol table used during encoding (indexed by h[n]) */
typedef struct p9_SymEntry
{
  char  name[P9OBJ_MAX_NAMELEN];
  int   dtype;    /* P9D_EXTERN or P9D_STATIC */
  int   stype;    /* STEXT / SDATA / SBSS / SXREF */
  long  value;    /* PC or data offset, assigned during span */
  int   version;  /* version for static disambiguation */
  int   bss_size; /* for AGLOBL / SBSS */
} p9_SymEntry;

#define P9_NSYM   50    /* per Plan 9 8.out.h NSYM */
#define P9_STEXT  1
#define P9_SDATA  2
#define P9_SBSS   3
#define P9_SXREF  5

/* Data record for ADATA */
typedef struct p9_DataRec
{
  int   sym_idx;    /* index into syms[] */
  long  offset;
  int   width;
  union {
    long   ival;
    struct { unsigned long l, h; } fval;
    char   sval[8];
    int    sym_ref;   /* sym_idx for a sym address datum */
  } val;
  int   is_sym_ref; /* val is a symbol address */
  int   sym_ref_type; /* D_EXTERN or D_STATIC */
} p9_DataRec;

/* ---- p9_oclass: classify an address for ytab matching ------------ */
static int
p9_oclass (const p9_Adr *a)
{
  long v;

  if (a->type >= P9D_INDIR || a->index != P9D_NONE)
    {
      if (a->index != P9D_NONE && a->scale == 0)
        {
          if (a->type == P9D_ADDR)
            {
              switch (a->index)
                {
                case P9D_EXTERN: case P9D_STATIC: return Yi32;
                case P9D_AUTO:   case P9D_PARAM:  return Yiauto;
                }
              return Yxxx;
            }
          return Ycol;
        }
      return Ym;
    }

  switch (a->type)
    {
    case P9D_AL:  return Yal;
    case P9D_AX:  return Yax;
    case P9D_CL:  return Ycl;
    case P9D_CX:  return Ycx;
    case P9D_DL: case P9D_BL: case P9D_AH: case P9D_CH:
    case P9D_DH: case P9D_BH: return Yrb;
    case P9D_DX: case P9D_BX: return Yrx;
    case P9D_SP: case P9D_BP: case P9D_SI: case P9D_DI: return Yrl;
    case P9D_F0:  return Yf0;
    case P9D_F0+1: case P9D_F0+2: case P9D_F0+3: case P9D_F0+4:
    case P9D_F0+5: case P9D_F0+6: case P9D_F0+7: return Yrf;
    case P9D_NONE: return Ynone;
    case P9D_CS:  return Ycs;
    case P9D_SS:  return Yss;
    case P9D_DS:  return Yds;
    case P9D_ES:  return Yes;
    case P9D_FS:  return Yfs;
    case P9D_GS:  return Ygs;
    case P9D_GDTR: return Ygdtr;
    case P9D_IDTR: return Yidtr;
    case P9D_LDTR: return Yldtr;
    case P9D_MSW:  return Ymsw;
    case P9D_TASK: return Ytask;

    case P9D_EXTERN: case P9D_STATIC: case P9D_AUTO: case P9D_PARAM:
      return Ym;

    case P9D_FCONST: case P9D_SCONST:
      return Yi32;

    case P9D_CONST: case P9D_ADDR:
      if (a->sym < 0)
        {
          v = a->offset;
          if (v == 0)  return Yi0;
          if (v == 1)  return Yi1;
          if (v >= -128 && v <= 127) return Yi8;
        }
      return Yi32;

    case P9D_BRANCH: return Ybr;
    }

  if (a->type >= P9D_CR && a->type <= P9D_CR + 7)
    return Ycr0 + (a->type - P9D_CR);
  if (a->type >= P9D_DR && a->type <= P9D_DR + 7)
    return Ydr0 + (a->type - P9D_DR);
  if (a->type >= P9D_TR && a->type <= P9D_TR + 7)
    return Ytr0 + (a->type - P9D_TR);

  return Yxxx;
}

/* ---- p9_put4: emit 4 bytes (LE) and note reloc if needed --------- */
static void
p9_put4 (p9_EncCtx *ctx, long v, int sym_idx, int pcrel, long field_pc)
{
  if (sym_idx >= 0)
    {
      /* record a relocation for this 4-byte field */
      if (ctx->n_relocs >= ctx->reloc_cap)
        {
          int newcap = ctx->reloc_cap ? ctx->reloc_cap * 2 : 16;
          int  *ns = (int *) realloc (ctx->reloc_syms,  newcap * sizeof(int));
          long *no = (long *) realloc (ctx->reloc_offsets, newcap * sizeof(long));
          int  *np = (int *) realloc (ctx->reloc_pcrls, newcap * sizeof(int));
          if (!ns || !no || !np) { free(ns); free(no); free(np); return; }
          ctx->reloc_syms    = ns;
          ctx->reloc_offsets = no;
          ctx->reloc_pcrls   = np;
          ctx->reloc_cap     = newcap;
        }
      ctx->reloc_syms   [ctx->n_relocs] = sym_idx;
      ctx->reloc_offsets[ctx->n_relocs] = field_pc;
      ctx->reloc_pcrls  [ctx->n_relocs] = pcrel;
      ctx->n_relocs++;
      /* For PC-relative, we already store 0 in the bytes (linker adjusts). */
      if (pcrel) v = 0;
    }
  ctx->andptr[0] = (unsigned char)(v);
  ctx->andptr[1] = (unsigned char)(v >> 8);
  ctx->andptr[2] = (unsigned char)(v >> 16);
  ctx->andptr[3] = (unsigned char)(v >> 24);
  ctx->andptr += 4;
}

/* ---- p9_vaddr: resolve address value (0 for external refs) ------- */
/* Returns the byte value AND sets ctx->reloc_sym if a reloc is needed. */
static long
p9_vaddr (const p9_Adr *a, int text_base_sym ATTRIBUTE_UNUSED,
          p9_EncCtx *ctx,
          const p9_SymEntry *syms, int nsyms, long cur_field_pc, int pcrel)
{
  int t;
  long v;
  int sym_idx;

  t = a->type;
  v = a->offset;
  sym_idx = -1;

  if (t == P9D_ADDR)
    t = a->index;

  switch (t)
    {
    case P9D_STATIC:
    case P9D_EXTERN:
      if (a->sym >= 0 && a->sym < nsyms)
        {
          const p9_SymEntry *s = &syms[a->sym];
          if (s->stype == P9_SXREF || s->stype == 0)
            {
              /* External/undefined: generate reloc */
              sym_idx = a->sym;
              v = 0; /* linker fills in */
            }
          else if (s->stype == P9_STEXT)
            {
              /* Defined in this file; use PC-relative offset */
              /* For now treat as reloc too so it is consistent */
              sym_idx = a->sym;
              v = s->value;
            }
          else
            {
              /* SDATA/SBSS – treat as reloc */
              sym_idx = a->sym;
              v = s->value;
            }
        }
      break;
    default:
      break;
    }

  /* If we need a reloc, record it */
  if (sym_idx >= 0)
    {
      if (ctx->n_relocs >= ctx->reloc_cap)
        {
          int newcap = ctx->reloc_cap ? ctx->reloc_cap * 2 : 16;
          int  *ns = (int *) realloc (ctx->reloc_syms,  newcap * sizeof(int));
          long *no = (long *) realloc (ctx->reloc_offsets, newcap * sizeof(long));
          int  *np = (int *) realloc (ctx->reloc_pcrls, newcap * sizeof(int));
          if (!ns || !no || !np) { free(ns); free(no); free(np); goto done; }
          ctx->reloc_syms    = ns;
          ctx->reloc_offsets = no;
          ctx->reloc_pcrls   = np;
          ctx->reloc_cap     = newcap;
        }
      ctx->reloc_syms   [ctx->n_relocs] = sym_idx;
      ctx->reloc_offsets[ctx->n_relocs] = cur_field_pc;
      ctx->reloc_pcrls  [ctx->n_relocs] = pcrel;
      ctx->n_relocs++;
      if (pcrel) v = 0;  /* linker adjusts */
    }
done:
  return v;
}

/* ---- SIB/ModRM helper -------------------------------------------- */
static void
p9_asmidx (p9_EncCtx *ctx, const p9_Adr *a, int base)
{
  int i;

  switch (a->index)
    {
    case P9D_NONE: i = 4 << 3; break;
    case P9D_AX: case P9D_CX: case P9D_DX: case P9D_BX:
    case P9D_BP: case P9D_SI: case P9D_DI:
      i = p9_reg[a->index] << 3; break;
    default: *ctx->andptr++ = 0; return;
    }

  switch (a->scale)
    {
    case 1: break;
    case 2: i |= (1<<6); break;
    case 4: i |= (2<<6); break;
    case 8: i |= (3<<6); break;
    default: *ctx->andptr++ = 0; return;
    }

  switch (base)
    {
    case P9D_NONE: i |= 5; break;
    case P9D_AX: case P9D_CX: case P9D_DX: case P9D_BX:
    case P9D_SP: case P9D_BP: case P9D_SI: case P9D_DI:
      i |= p9_reg[base]; break;
    default: *ctx->andptr++ = 0; return;
    }

  *ctx->andptr++ = (unsigned char) i;
}

/* ---- p9_asmand: emit ModRM/SIB for one operand ------------------- */
static void
p9_asmand (p9_EncCtx *ctx, const p9_Adr *a, int r,
           const p9_SymEntry *syms, int nsyms)
{
  long v;
  int t;
  p9_Adr aa;

  v = a->offset;
  t = a->type;

  if (a->index != P9D_NONE)
    {
      if (t >= P9D_INDIR)
        {
          t -= P9D_INDIR;
          if (t == P9D_NONE)
            {
              *ctx->andptr++ = (unsigned char)((0<<6)|(4<<0)|(r<<3));
              p9_asmidx (ctx, a, t);
              { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
                v = p9_vaddr(a, -1, ctx, syms, nsyms, fpc, 0); }
              p9_put4 (ctx, v, -1, 0, 0);
              return;
            }
          if (v == 0 && t != P9D_BP)
            {
              *ctx->andptr++ = (unsigned char)((0<<6)|(4<<0)|(r<<3));
              p9_asmidx (ctx, a, t);
              return;
            }
          if (v >= -128 && v < 128)
            {
              *ctx->andptr++ = (unsigned char)((1<<6)|(4<<0)|(r<<3));
              p9_asmidx (ctx, a, t);
              *ctx->andptr++ = (unsigned char) v;
              return;
            }
          *ctx->andptr++ = (unsigned char)((2<<6)|(4<<0)|(r<<3));
          p9_asmidx (ctx, a, t);
          { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
            p9_put4(ctx, v, -1, 0, fpc); }
          return;
        }

      /* indirect with index, base from sym type */
      switch (t)
        {
        case P9D_STATIC: case P9D_EXTERN:
          aa.type = P9D_NONE + P9D_INDIR; break;
        case P9D_AUTO: case P9D_PARAM:
          aa.type = P9D_SP + P9D_INDIR; break;
        default: return;
        }
      aa.offset = a->offset; /* vaddr resolved by caller */
      aa.index  = a->index;
      aa.scale  = a->scale;
      aa.sym    = a->sym;
      p9_asmand (ctx, &aa, r, syms, nsyms);
      return;
    }

  /* Register operand */
  if (t >= P9D_AL && t <= P9D_F0 + 7)
    {
      *ctx->andptr++ = (unsigned char)((3<<6)|(p9_reg[t]<<0)|(r<<3));
      return;
    }

  if (t >= P9D_INDIR)
    {
      t -= P9D_INDIR;
      if (t == P9D_NONE || (t >= P9D_CS && t <= P9D_GS))
        {
          long fpc;
          *ctx->andptr++ = (unsigned char)((0<<6)|(5<<0)|(r<<3));
          fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
          { int sid = (a->sym >= 0 && a->sym < nsyms) ? a->sym : -1;
            int pcr = 0;
            p9_put4(ctx, v, sid, pcr, fpc); }
          return;
        }
      if (t == P9D_SP)
        {
          if (v == 0)
            {
              *ctx->andptr++ = (unsigned char)((0<<6)|(4<<0)|(r<<3));
              { p9_Adr tmp = *a; tmp.type = P9D_SP; tmp.scale = 1;
                p9_asmidx(ctx, &tmp, P9D_SP); }
              return;
            }
          if (v >= -128 && v < 128)
            {
              *ctx->andptr++ = (unsigned char)((1<<6)|(4<<0)|(r<<3));
              { p9_Adr tmp = *a; tmp.type = P9D_SP; tmp.scale = 1;
                p9_asmidx(ctx, &tmp, P9D_SP); }
              *ctx->andptr++ = (unsigned char) v;
              return;
            }
          *ctx->andptr++ = (unsigned char)((2<<6)|(4<<0)|(r<<3));
          { p9_Adr tmp = *a; tmp.type = P9D_SP; tmp.scale = 1;
            p9_asmidx(ctx, &tmp, P9D_SP); }
          { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
            p9_put4(ctx, v, -1, 0, fpc); }
          return;
        }
      if (t >= P9D_AX && t <= P9D_DI)
        {
          if (v == 0 && t != P9D_BP)
            {
              *ctx->andptr++ = (unsigned char)((0<<6)|(p9_reg[t]<<0)|(r<<3));
              return;
            }
          if (v >= -128 && v < 128)
            {
              *ctx->andptr++ = (unsigned char)((1<<6)|(p9_reg[t]<<0)|(r<<3));
              *ctx->andptr++ = (unsigned char) v;
              return;
            }
          *ctx->andptr++ = (unsigned char)((2<<6)|(p9_reg[t]<<0)|(r<<3));
          { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
            p9_put4(ctx, v, -1, 0, fpc); }
          return;
        }
      return;
    }

  /* D_STATIC / D_EXTERN / D_AUTO / D_PARAM without index */
  switch (a->type)
    {
    case P9D_STATIC: case P9D_EXTERN:
      aa.type = P9D_NONE + P9D_INDIR; break;
    case P9D_AUTO: case P9D_PARAM:
      aa.type = P9D_SP + P9D_INDIR; break;
    default: return;
    }
  aa.index  = P9D_NONE;
  aa.scale  = 1;
  aa.offset = a->offset;
  aa.sym    = a->sym;
  p9_asmand (ctx, &aa, r, syms, nsyms);
}

/* ---- p9_doasm: encode one instruction into ctx->and_buf ---------- */
static void
p9_doasm (p9_EncCtx *ctx, const p9_Prog *p, const p9_Prog *progs, int nprogs,
          const p9_SymEntry *syms, int nsyms)
{
  const p9_Optab *o;
  const unsigned char *t;
  int z, op, ft, tt;
  long v;
  int pre;
  long from_v;

  if (p->as <= 0 || p->as >= P9AS_LAST) return;
  o = &p9_optab[p->as];
  if (o->ytab == NULL) return;  /* unimplemented opcode */

  /* Emit segment prefix if needed */
  pre = 0;
  switch (p->from.type) {
  case P9D_INDIR + P9D_CS: pre = 0x2e; break;
  case P9D_INDIR + P9D_DS: pre = 0x3e; break;
  case P9D_INDIR + P9D_ES: pre = 0x26; break;
  case P9D_INDIR + P9D_FS: pre = 0x64; break;
  case P9D_INDIR + P9D_GS: pre = 0x65; break;
  }
  if (pre) *ctx->andptr++ = (unsigned char) pre;
  pre = 0;
  switch (p->to.type) {
  case P9D_INDIR + P9D_CS: pre = 0x2e; break;
  case P9D_INDIR + P9D_DS: pre = 0x3e; break;
  case P9D_INDIR + P9D_ES: pre = 0x26; break;
  case P9D_INDIR + P9D_FS: pre = 0x64; break;
  case P9D_INDIR + P9D_GS: pre = 0x65; break;
  }
  if (pre) *ctx->andptr++ = (unsigned char) pre;

  /* CALL/JMP to external symbol: must emit direct E8/E9 rel32, not FF/2 or
     FF/4 (indirect-through-memory).  In Plan 9 assembler "CALL sym(SB)"
     means a direct near-call; only "CALL *(mem)" is indirect.
     p9_oclass() maps P9D_EXTERN/P9D_STATIC to Ym which would pick Zo_m
     (FF /2) before the Zcall/Zjmp (E8/E9) entries in p9_ycall/p9_yjmp, so
     we intercept here and emit the direct form explicitly.  */
  if ((p->as == P9AS_CALL || p->as == P9AS_JMP)
      && (p->to.type == P9D_EXTERN || p->to.type == P9D_STATIC)
      && p->to.sym >= 0)
    {
      long fpc;
      *ctx->andptr++ = (p->as == P9AS_CALL) ? 0xe8 : 0xe9;
      fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
      p9_put4 (ctx, 0, p->to.sym, 1, fpc);
      return;
    }

  ft = p9_oclass (&p->from) * Ymax;
  tt = p9_oclass (&p->to)   * Ymax;
  t  = o->ytab;

  for (z = 0; *t; z += t[3], t += 4)
    if (p9_ycover[ft + t[0]] && p9_ycover[tt + t[1]])
      goto found;
  goto domov;

found:
  switch (o->prefix)
    {
    case Pq: *ctx->andptr++ = 0x66; *ctx->andptr++ = 0x0f; break;
    case Pm: *ctx->andptr++ = 0x0f; break;
    case Pe: *ctx->andptr++ = 0x66; break;
    case Pb: break;
    default: break;
    }

  /* Resolve from value for use in immediate fields */
  { long fpc0 = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
    if (p->from.sym >= 0 && p->from.sym < nsyms
        && (p->from.type == P9D_EXTERN || p->from.type == P9D_STATIC
            || p->from.type == P9D_ADDR))
      { from_v = 0; /* reloc will handle it */ }
    else
      from_v = p->from.offset;
    (void)fpc0;
  }
  v = from_v;

  op = o->op[z];
  switch (t[2])
    {
    case Zpseudo: break;

    case Zlit:
      for (; (op = o->op[z]) != 0; z++)
        *ctx->andptr++ = op;
      break;

    case Zm_r:
      *ctx->andptr++ = op;
      p9_asmand (ctx, &p->from, p9_reg[p->to.type], syms, nsyms);
      break;

    case Zaut_r:
      *ctx->andptr++ = 0x8d; /* leal */
      { p9_Adr tmp = p->from;
        tmp.type  = tmp.index;
        tmp.index = P9D_NONE;
        p9_asmand (ctx, &tmp, p9_reg[p->to.type], syms, nsyms); }
      break;

    case Zm_o:
      *ctx->andptr++ = op;
      p9_asmand (ctx, &p->from, o->op[z+1], syms, nsyms);
      break;

    case Zr_m:
      *ctx->andptr++ = op;
      p9_asmand (ctx, &p->to, p9_reg[p->from.type], syms, nsyms);
      break;

    case Zo_m:
      *ctx->andptr++ = op;
      p9_asmand (ctx, &p->to, o->op[z+1], syms, nsyms);
      break;

    case Zm_ibo:
      { long tv = p->to.offset;
        *ctx->andptr++ = op;
        p9_asmand (ctx, &p->from, o->op[z+1], syms, nsyms);
        *ctx->andptr++ = (unsigned char) tv; }
      break;

    case Zibo_m:
      *ctx->andptr++ = op;
      p9_asmand (ctx, &p->to, o->op[z+1], syms, nsyms);
      *ctx->andptr++ = (unsigned char) v;
      break;

    case Z_ib:
      v = p->to.offset;
      /* FALLTHROUGH */
    case Zib_:
      *ctx->andptr++ = op;
      *ctx->andptr++ = (unsigned char) v;
      break;

    case Zib_rp:
      *ctx->andptr++ = op + p9_reg[p->to.type];
      *ctx->andptr++ = (unsigned char) v;
      break;

    case Zil_rp:
      *ctx->andptr++ = op + p9_reg[p->to.type];
      if (o->prefix == Pe)
        { *ctx->andptr++ = (unsigned char) v;
          *ctx->andptr++ = (unsigned char)(v >> 8); }
      else
        { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
          int  sid = (p->from.sym >= 0) ? p->from.sym : -1;
          p9_put4 (ctx, v, sid, 0, fpc); }
      break;

    case Zib_rr:
      *ctx->andptr++ = op;
      p9_asmand (ctx, &p->to, p9_reg[p->to.type], syms, nsyms);
      *ctx->andptr++ = (unsigned char) v;
      break;

    case Z_il:
      v = p->to.offset;
      /* FALLTHROUGH */
    case Zil_:
      *ctx->andptr++ = op;
      if (o->prefix == Pe)
        { *ctx->andptr++ = (unsigned char) v;
          *ctx->andptr++ = (unsigned char)(v >> 8); }
      else
        { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
          p9_put4 (ctx, v, -1, 0, fpc); }
      break;

    case Zm_ilo:
      { long tv; int tsid;
        tv   = p->to.offset;
        tsid = (p->to.sym >= 0) ? p->to.sym : -1;
        *ctx->andptr++ = op;
        p9_asmand (ctx, &p->from, o->op[z+1], syms, nsyms);
        { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
          p9_put4 (ctx, tv, tsid, 0, fpc); } }
      break;

    case Zilo_m:
      *ctx->andptr++ = op;
      p9_asmand (ctx, &p->to, o->op[z+1], syms, nsyms);
      if (o->prefix == Pe)
        { *ctx->andptr++ = (unsigned char) v;
          *ctx->andptr++ = (unsigned char)(v >> 8); }
      else
        { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
          int  sid = (p->from.sym >= 0) ? p->from.sym : -1;
          p9_put4 (ctx, v, sid, 0, fpc); }
      break;

    case Zil_rr:
      *ctx->andptr++ = op;
      p9_asmand (ctx, &p->to, p9_reg[p->to.type], syms, nsyms);
      if (o->prefix == Pe)
        { *ctx->andptr++ = (unsigned char) v;
          *ctx->andptr++ = (unsigned char)(v >> 8); }
      else
        { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
          p9_put4 (ctx, v, -1, 0, fpc); }
      break;

    case Z_rp:
      *ctx->andptr++ = op + p9_reg[p->to.type];
      break;

    case Zrp_:
      *ctx->andptr++ = op + p9_reg[p->from.type];
      break;

    case Zclr:
      *ctx->andptr++ = op;
      p9_asmand (ctx, &p->to, p9_reg[p->to.type], syms, nsyms);
      break;

    case Zbr:
      /* Conditional branch */
      if (p->pcond_idx >= 0 && p->pcond_idx < nprogs)
        {
          long q_pc = progs[p->pcond_idx].pc;
          v = q_pc - p->pc - 2;
          if (v >= -128 && v <= 127)
            { *ctx->andptr++ = op;
              *ctx->andptr++ = (unsigned char) v; }
          else
            { v -= 6 - 2; /* short → long form delta */
              *ctx->andptr++ = 0x0f;
              *ctx->andptr++ = o->op[z+1];
              ctx->andptr[0] = (unsigned char) v;
              ctx->andptr[1] = (unsigned char)(v >> 8);
              ctx->andptr[2] = (unsigned char)(v >> 16);
              ctx->andptr[3] = (unsigned char)(v >> 24);
              ctx->andptr   += 4; }
        }
      break;

    case Zcall:
      /* CALL – always long form (5 bytes); may need reloc */
      *ctx->andptr++ = op;
      { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
        if (p->to.type == P9D_BRANCH && p->pcond_idx >= 0)
          {
            long q_pc = progs[p->pcond_idx].pc;
            v = q_pc - (p->pc + 5);
            p9_put4 (ctx, v, -1, 0, fpc);
          }
        else
          {
            /* external symbol call */
            int  sid = (p->to.sym >= 0) ? p->to.sym : -1;
            p9_put4 (ctx, 0, sid, 1, fpc);
          } }
      break;

    case Zjmp:
      /* Unconditional JMP */
      if (p->pcond_idx >= 0 && p->pcond_idx < nprogs)
        {
          long q_pc = progs[p->pcond_idx].pc;
          v = q_pc - p->pc - 2;
          if (v >= -128 && v <= 127)
            { *ctx->andptr++ = op;
              *ctx->andptr++ = (unsigned char) v; }
          else
            { v -= 5 - 2;
              *ctx->andptr++ = o->op[z+1]; /* 0xe9 long jmp */
              ctx->andptr[0] = (unsigned char) v;
              ctx->andptr[1] = (unsigned char)(v >> 8);
              ctx->andptr[2] = (unsigned char)(v >> 16);
              ctx->andptr[3] = (unsigned char)(v >> 24);
              ctx->andptr   += 4; }
        }
      else
        {
          /* JMP to external symbol */
          *ctx->andptr++ = 0xe9;
          { long fpc = ctx->cur_pc + (ctx->andptr - ctx->and_buf);
            int  sid = (p->to.sym >= 0) ? p->to.sym : -1;
            p9_put4 (ctx, 0, sid, 1, fpc); }
        }
      break;

    case Zloop:
      if (p->pcond_idx >= 0 && p->pcond_idx < nprogs)
        {
          long q_pc = progs[p->pcond_idx].pc;
          v = q_pc - p->pc - 2;
          *ctx->andptr++ = op;
          *ctx->andptr++ = (unsigned char) v;
        }
      break;

    case Zbyte:
      ctx->andptr[0] = (unsigned char) v;
      ctx->andptr++;
      if (op > 1) { ctx->andptr[0] = (unsigned char)(v>>8); ctx->andptr++; }
      if (op > 2) {
        ctx->andptr[0] = (unsigned char)(v>>16); ctx->andptr++;
        ctx->andptr[0] = (unsigned char)(v>>24); ctx->andptr++;
      }
      break;

    case Zmov: goto domov;
    }
  return;

domov:
  { const unsigned char *mt;
    for (mt = p9_ymovtab; *mt; mt += 8)
      if (p->as == mt[0]
          && p9_ycover[ft + mt[1]]
          && p9_ycover[tt + mt[2]])
        {
          switch (mt[3])
            {
            case 0: /* literal bytes */
              { int zi; for (zi = 4; mt[zi] != YMOV_E; zi++) *ctx->andptr++ = mt[zi]; }
              return;
            case 1: /* r→m 2-byte */
              *ctx->andptr++ = mt[4];
              p9_asmand (ctx, &p->to, mt[5], syms, nsyms);
              return;
            case 2: /* m→r 2-byte */
              *ctx->andptr++ = mt[4];
              p9_asmand (ctx, &p->from, mt[5], syms, nsyms);
              return;
            case 3: /* r→m 3-byte */
              *ctx->andptr++ = mt[4]; *ctx->andptr++ = mt[5];
              p9_asmand (ctx, &p->to, mt[6], syms, nsyms);
              return;
            case 4: /* m→r 3-byte */
              *ctx->andptr++ = mt[4]; *ctx->andptr++ = mt[5];
              p9_asmand (ctx, &p->from, mt[6], syms, nsyms);
              return;
            }
        } }
  return;
}

/* ---- p9_asmins: encode p into ctx->and_buf, return byte count ---- */
static int
p9_asmins (p9_EncCtx *ctx, const p9_Prog *p, const p9_Prog *progs, int nprogs,
           const p9_SymEntry *syms, int nsyms)
{
  ctx->andptr = ctx->and_buf;
  p9_doasm (ctx, p, progs, nprogs, syms, nsyms);
  return (int)(ctx->andptr - ctx->and_buf);
}


/* ---- p9_read_zaddr: parse one zaddr from binary stream ------------ */
/* Returns bytes consumed, or -1 on error.
   Fills *a with the decoded address.
   h[] maps symbol index -> sym_table index (-1 = unknown).  */
static int
p9_read_zaddr (const unsigned char *p, bfd_size_type rem,
               p9_Adr *a, const int *h_symidx, int nsyms_in_h)
{
  unsigned int t, c;
  (void) nsyms_in_h;

  if (rem < 1) return -1;
  t = p[0];
  c = 1;

  a->index = P9D_NONE;
  a->scale = 1;
  a->offset = 0;
  a->sym = -1;
  a->type = P9D_NONE;
  a->fconst_l = a->fconst_h = 0;
  memset (a->sconst, 0, sizeof (a->sconst));

  if (t & P9OBJ_T_INDEX)
    {
      if (c + 2 > rem) return -1;
      a->index = (short) p[c];
      a->scale = p[c + 1];
      c += 2;
    }
  if (t & P9OBJ_T_OFFSET)
    {
      if (c + 4 > rem) return -1;
      /* Use BFD's signed 32-bit LE reader so that negative offsets
         (e.g. D_AUTO -0x40 = 0xffffffc0) are correctly sign-extended
         to the native long width on both 32-bit and 64-bit hosts.
         Without sign extension, -0x40 would become a large positive
         long on 64-bit, defeating the 8-bit displacement optimisation
         and breaking the D_AUTO offset arithmetic.  */
      a->offset = (long) bfd_getl_signed_32 (p + c);
      c += 4;
    }
  if (t & P9OBJ_T_SYM)
    {
      if (c >= rem) return -1;
      { unsigned int si = p[c++];
        a->sym = (si < 256 && h_symidx[si] >= 0) ? h_symidx[si] : -1; }
    }
  if (t & P9OBJ_T_FCONST)
    {
      if (c + 8 > rem) return -1;
      a->fconst_l = ((unsigned long)p[c]   | ((unsigned long)p[c+1]<<8)
                   | ((unsigned long)p[c+2]<<16) | ((unsigned long)p[c+3]<<24));
      a->fconst_h = ((unsigned long)p[c+4] | ((unsigned long)p[c+5]<<8)
                   | ((unsigned long)p[c+6]<<16) | ((unsigned long)p[c+7]<<24));
      c += 8;
      a->type = P9D_FCONST;
    }
  else if (t & P9OBJ_T_SCONST)
    {
      int i;
      if (c + P9OBJ_NSNAME > rem) return -1;
      for (i = 0; i < P9OBJ_NSNAME; i++) a->sconst[i] = (char)p[c+i];
      c += P9OBJ_NSNAME;
      a->type = P9D_SCONST;
    }
  if (t & P9OBJ_T_TYPE)
    {
      if (c >= rem) return -1;
      a->type = (short) p[c++];
    }
  return (int) c;
}

/* ---- p9obj_encode_file: main Phase 2 entry point ----------------- */
/* Reads the .8 stream, encodes instructions, fills tdata with:
     text_content, text_size, data_content, data_size, bss_size,
     text_relocs, text_nrelocs.
   Also sets correct values in tdata->symbols.
   Must be called AFTER p9obj_slurp_symtab or will call it first.  */
static int
p9obj_encode_file (bfd *abfd, asection *text_sec ATTRIBUTE_UNUSED,
                   asection *data_sec ATTRIBUTE_UNUSED,
                   asection *bss_sec  ATTRIBUTE_UNUSED)
{
  struct plan9_out_i386_tdata *tdata = plan9_out_i386_tdata (abfd);
  bfd_byte *buf  = NULL;
  bfd_size_type  file_size, pos;

  /* Internal symbol table */
  p9_SymEntry   int_syms[P9_NSYM * 4];   /* internal encoding symbols   */
  int           h_symidx[256];            /* h[n] → index in int_syms[] */
  int           n_int_syms = 0;
  int           cur_version = 0;

  /* Prog (instruction) array */
  p9_Prog       *progs     = NULL;
  int            nprogs    = 0, progs_cap = 0;
  p9_Prog       *progs_all = NULL;  /* concat of all functions */
  int            nprogs_all = 0, progs_all_cap = 0;

  /* Data record array */
  p9_DataRec    *datarecs  = NULL;
  int            ndatarecs = 0, datarecs_cap = 0;

  /* Current function context */
  int cur_text_sym = -1;  /* index in int_syms of current ATEXT sym */
  long text_pc     = 0;   /* cumulative PC across all functions      */
  long data_total  = 0;   /* total .data bytes                       */
  long bss_total   = 0;   /* total .bss bytes                        */

  /* Function-relative instruction counter used for D_BRANCH resolution.
     In Plan 9 .8 files, D_BRANCH target offsets are FUNCTION-RELATIVE
     instruction indices: the ATEXT record itself is index 0, the first
     real instruction is 1, the second is 2, and so on.  They are NOT
     byte offsets into the encoded text and NOT file-global counters.
     This counter is reset to 0 at each ATEXT record (see below) and
     incremented for every subsequent non-ANAME record (including
     AHISTORY records within the function body, which 8a also counts).
     The resulting value is stored in p9_Prog.back; branch-target
     resolution matches back == D_BRANCH.offset.  */
  int global_plan9_pc = 0;

  /* Encoding context */
  p9_EncCtx ctx;
  bfd_byte *text_buf = NULL;
  bfd_size_type text_buf_cap = 0;
  bfd_byte *data_buf = NULL;
  bfd_size_type data_buf_cap = 0;

  int i, pass, again;
  long c;

  if (tdata->encoded)
    return 1;  /* already done */

  /* Ensure the symbol table is built first so we can correlate symbols */
  if (!p9obj_slurp_symtab (abfd))
    return 0;

  /* ---- Read the file into memory ---- */
  if (bfd_seek (abfd, 0, SEEK_SET) != 0)
    return 0;
  file_size = bfd_get_size (abfd);
  if (file_size == 0) { tdata->encoded = 1; return 1; }

  buf = (bfd_byte *) bfd_malloc (file_size);
  if (buf == NULL) return 0;
  if (bfd_bread (buf, file_size, abfd) != file_size) { free(buf); return 0; }

  /* ---- Initialize internal symbol map ---- */
  memset (h_symidx, -1, sizeof(h_symidx));
  memset (int_syms, 0,  sizeof(int_syms));

  /* ---- First pass: scan stream, build internal syms, collect progs ---- */
  pos = 0;
  while (pos + 2 <= file_size)
    {
      unsigned int opcode;
      bfd_size_type rem;

      opcode = (unsigned int)buf[pos] | ((unsigned int)buf[pos+1] << 8);
      rem    = file_size - pos;

      /* ---- ANAME / ASIGNAME ---- */
      if (opcode == P9OBJ_ANAME || opcode == P9OBJ_ASIGNAME)
        {
          bfd_size_type hdr_off = (opcode == P9OBJ_ASIGNAME) ? 6 : 2;
          unsigned int dtype, sidx;
          const char *name;
          unsigned char *nulp;
          int  is_static;

          if (pos + hdr_off + 2 > file_size) break;
          dtype = buf[pos + hdr_off];
          sidx  = buf[pos + hdr_off + 1];
          name  = (const char *)(buf + pos + hdr_off + 2);

          nulp = (unsigned char *) memchr (name, 0,
                                           file_size - (pos + hdr_off + 2));
          if (nulp == NULL) break;
          pos = (bfd_size_type)(nulp - buf) + 1;

          if (sidx >= 256) continue;

          if (dtype == P9D_EXTERN || dtype == P9D_STATIC)
            {
              /* Register in int_syms if not already present */
              int found = -1, fi;
              is_static = (dtype == P9D_STATIC);
              for (fi = 0; fi < n_int_syms; fi++)
                {
                  if (strcmp (int_syms[fi].name, name) == 0
                      && (is_static ? int_syms[fi].version != 0
                                    : int_syms[fi].version == 0))
                    { found = fi; break; }
                }
              if (found < 0)
                {
                  if (n_int_syms >= (int)(sizeof(int_syms)/sizeof(int_syms[0])))
                    { h_symidx[sidx] = -1; continue; }
                  found = n_int_syms++;
                  strncpy (int_syms[found].name, name,
                           sizeof(int_syms[found].name) - 1);
                  int_syms[found].dtype  = dtype;
                  int_syms[found].stype  = P9_SXREF;
                  int_syms[found].value  = 0;
                  int_syms[found].version = is_static ? ++cur_version : 0;
                  int_syms[found].bss_size = 0;
                }
              h_symidx[sidx] = found;
            }
          else if (dtype == P9OBJ_D_FILE || dtype == P9OBJ_D_FILE1)
            h_symidx[sidx] = -1;  /* not a real sym */
          continue;
        }

      /* ---- Non-ANAME records: [2-byte op][4-byte line][from][to] ---- */
      if (rem < 7) break;

      { int fsz, tsz;
        fsz = p9obj_zaddr_size (buf + pos + 6, rem - 6);
        if (fsz < 0) break;
        tsz = p9obj_zaddr_size (buf + pos + 6 + (bfd_size_type)fsz,
                                rem - 6 - (bfd_size_type)fsz);
        if (tsz < 0) break;

        /* ---- AEND: end of object ---- */
        if (opcode == P9OBJ_AEND)
          { pos += 2 + 4 + (bfd_size_type)fsz + (bfd_size_type)tsz;
            break; }

        /* ---- ATEXT: start of function ---- */
        if (opcode == P9OBJ_ATEXT)
          {
            p9_Adr from_a, to_a;
            int fr, tr;

            /* D_BRANCH targets in Plan 9 .8 files are function-relative
               instruction indices where ATEXT itself = 0.  Reset the
               counter here so that progs[].back values match what 8a/8l
               stores in D_BRANCH.offset.  The common global_plan9_pc++
               at the bottom of the loop will advance it to 1 for the
               first real instruction, which is correct (TEXT=0, first
               real instr=1, …).  */
            global_plan9_pc = 0;

            fr = p9_read_zaddr (buf + pos + 6, rem - 6,
                                 &from_a, h_symidx, 256);
            tr = p9_read_zaddr (buf + pos + 6 + (fr > 0 ? fr : 0),
                                 rem - 6 - (fr > 0 ? (bfd_size_type)fr : 0),
                                 &to_a, h_symidx, 256);
            (void)tr;

            /* Flush any previously accumulated progs for the last function */
            if (progs && nprogs > 0)
              {
                /* Append to progs_all */
                if (nprogs_all + nprogs > progs_all_cap)
                  {
                    int newcap = progs_all_cap ? progs_all_cap * 2 : 64;
                    while (newcap < nprogs_all + nprogs) newcap *= 2;
                    p9_Prog *np = (p9_Prog *) realloc (progs_all,
                                    newcap * sizeof(p9_Prog));
                    if (!np) goto out_err;
                    progs_all = np;
                    progs_all_cap = newcap;
                  }
                memcpy (progs_all + nprogs_all, progs,
                        nprogs * sizeof(p9_Prog));
                nprogs_all += nprogs;
                nprogs = 0;
              }
            if (!progs)
              {
                progs_cap = 64;
                progs = (p9_Prog *) malloc (progs_cap * sizeof(p9_Prog));
                if (!progs) goto out_err;
              }

            /* Set symbol type and value (PC is assigned later by span) */
            cur_text_sym = (fr > 0) ? from_a.sym : -1;
            if (cur_text_sym >= 0 && cur_text_sym < n_int_syms)
              {
                int_syms[cur_text_sym].stype = P9_STEXT;
                /* value will be set to text_pc during span */
              }

            /* Add the ATEXT prog */
            if (nprogs >= progs_cap)
              {
                progs_cap *= 2;
                p9_Prog *np = (p9_Prog *) realloc (progs,
                                progs_cap * sizeof(p9_Prog));
                if (!np) goto out_err;
                progs = np;
              }
            memset (&progs[nprogs], 0, sizeof(p9_Prog));
            progs[nprogs].as   = P9AS_TEXT;
            progs[nprogs].from = from_a;
            progs[nprogs].to   = to_a;
            progs[nprogs].pcond_idx = -1;
            progs[nprogs].back = global_plan9_pc;  /* = 0 (function-relative) */
            /* Store function sym idx in a spare field for later */
            progs[nprogs].pc   = (cur_text_sym >= 0) ? cur_text_sym : -1;
            nprogs++;

            /* In Plan 9 object format, the ATEXT instruction's to.offset
               holds the auto (stack frame) size.  This is the size the Plan 9
               linker (8l) uses to synthesise ADJSP at the start of every
               function: TEXT foo(SB),$N  →  ADJSP $N  (= sub $N,%esp).
               If the .8 file contains no explicit ADJSP instruction (which is
               the case for real 9front libc objects), we inject one here so
               the disassembly shows the correct stack allocation.
               The ADJSP→SUBL/ADDL/NOP conversion is handled later in the
               ADJSP pass below.  */
            if (to_a.offset > 0)
              {
                if (nprogs >= progs_cap)
                  {
                    progs_cap *= 2;
                    p9_Prog *np = (p9_Prog *) realloc (progs,
                                    progs_cap * sizeof(p9_Prog));
                    if (!np) goto out_err;
                    progs = np;
                  }
                memset (&progs[nprogs], 0, sizeof(p9_Prog));
                progs[nprogs].as            = P9AS_ADJSP;
                progs[nprogs].from.type     = P9D_CONST;
                progs[nprogs].from.offset   = to_a.offset;
                progs[nprogs].from.sym      = -1;
                progs[nprogs].from.index    = P9D_NONE;
                progs[nprogs].from.scale    = 1;
                progs[nprogs].to.type       = P9D_NONE;
                progs[nprogs].to.sym        = -1;
                progs[nprogs].pcond_idx     = -1;
                progs[nprogs].back          = -1;  /* synthetic: no Plan 9 pc */
                nprogs++;
              }
          }
        /* ---- AGLOBL: BSS declaration ---- */
        else if (opcode == P9OBJ_AGLOBL)
          {
            p9_Adr from_a, to_a;
            int fr, tr;
            fr = p9_read_zaddr (buf + pos + 6, rem - 6,
                                 &from_a, h_symidx, 256);
            tr = p9_read_zaddr (buf + pos + 6 + (fr > 0 ? fr : 0),
                                 rem - 6 - (fr > 0 ? (bfd_size_type)fr : 0),
                                 &to_a, h_symidx, 256);
            (void)tr;
            if (fr > 0 && from_a.sym >= 0 && from_a.sym < n_int_syms)
              {
                int si = from_a.sym;
                long sz = to_a.offset;
                if (int_syms[si].stype == P9_SXREF
                    || int_syms[si].stype == 0)
                  {
                    int_syms[si].stype = P9_SBSS;
                    int_syms[si].value = 0; /* will be assigned later */
                  }
                if (sz > int_syms[si].bss_size)
                  int_syms[si].bss_size = (int) sz;
              }
          }
        /* ---- ADATA: data record ---- */
        else if (opcode == P9OBJ_ADATA)
          {
            p9_Adr from_a, to_a;
            int fr, tr;
            fr = p9_read_zaddr (buf + pos + 6, rem - 6,
                                 &from_a, h_symidx, 256);
            tr = p9_read_zaddr (buf + pos + 6 + (fr > 0 ? fr : 0),
                                 rem - 6 - (fr > 0 ? (bfd_size_type)fr : 0),
                                 &to_a, h_symidx, 256);
            (void)tr;
            if (fr > 0 && from_a.sym >= 0 && from_a.sym < n_int_syms)
              {
                int si = from_a.sym;
                if (int_syms[si].stype == P9_SXREF
                    || int_syms[si].stype == 0)
                  int_syms[si].stype = P9_SDATA;

                /* Collect the data record */
                if (ndatarecs >= datarecs_cap)
                  {
                    datarecs_cap = datarecs_cap ? datarecs_cap * 2 : 16;
                    p9_DataRec *nd = (p9_DataRec *) realloc (datarecs,
                                       datarecs_cap * sizeof(p9_DataRec));
                    if (!nd) goto out_err;
                    datarecs = nd;
                  }
                memset (&datarecs[ndatarecs], 0, sizeof(p9_DataRec));
                datarecs[ndatarecs].sym_idx = si;
                datarecs[ndatarecs].offset  = from_a.offset;
                datarecs[ndatarecs].width   = from_a.scale ? from_a.scale : 4;
                if (to_a.type == P9D_FCONST)
                  {
                    datarecs[ndatarecs].val.fval.l = (unsigned long)to_a.fconst_l;
                    datarecs[ndatarecs].val.fval.h = (unsigned long)to_a.fconst_h;
                  }
                else if (to_a.type == P9D_SCONST)
                  memcpy (datarecs[ndatarecs].val.sval, to_a.sconst, 8);
                else if (to_a.type == P9D_ADDR
                         || to_a.type == P9D_EXTERN
                         || to_a.type == P9D_STATIC)
                  {
                    datarecs[ndatarecs].is_sym_ref = 1;
                    datarecs[ndatarecs].val.sym_ref = to_a.sym;
                    datarecs[ndatarecs].sym_ref_type = to_a.type;
                    datarecs[ndatarecs].val.ival = to_a.offset;
                  }
                else
                  datarecs[ndatarecs].val.ival = to_a.offset;
                ndatarecs++;
              }
          }
        /* ---- Regular instruction ---- */
        else if (opcode != P9OBJ_AHISTORY && cur_text_sym >= 0)
          {
            p9_Adr from_a, to_a;
            int fr, tr;
            if (nprogs >= progs_cap)
              {
                int nc = progs_cap ? progs_cap * 2 : 64;
                p9_Prog *np = (p9_Prog *) realloc (progs,
                                nc * sizeof(p9_Prog));
                if (!np) goto out_err;
                progs = np;
                progs_cap = nc;
              }

            fr = p9_read_zaddr (buf + pos + 6, rem - 6,
                                 &from_a, h_symidx, 256);
            if (fr < 0) fr = 1;
            tr = p9_read_zaddr (buf + pos + 6 + (bfd_size_type)fr,
                                 rem - 6 - (bfd_size_type)fr,
                                 &to_a, h_symidx, 256);
            if (tr < 0) tr = 1;

            memset (&progs[nprogs], 0, sizeof(p9_Prog));
            progs[nprogs].as   = (short) opcode;
            progs[nprogs].from = from_a;
            progs[nprogs].to   = to_a;
            progs[nprogs].back = global_plan9_pc;  /* function-relative index */
            progs[nprogs].pcond_idx = -1;
            nprogs++;
          }

        pos += 2 + 4 + (bfd_size_type)fsz + (bfd_size_type)tsz;
        global_plan9_pc++;  /* count every non-ANAME record (function-relative) */
      }
    } /* end while */

  free (buf);
  buf = NULL;

  /* Flush last function's progs */
  if (progs && nprogs > 0)
    {
      if (nprogs_all + nprogs > progs_all_cap)
        {
          int newcap = progs_all_cap ? progs_all_cap * 2 : 64;
          while (newcap < nprogs_all + nprogs) newcap *= 2;
          p9_Prog *np = (p9_Prog *) realloc (progs_all,
                          newcap * sizeof(p9_Prog));
          if (!np) goto out_err;
          progs_all = np;
          progs_all_cap = newcap;
        }
      memcpy (progs_all + nprogs_all, progs, nprogs * sizeof(p9_Prog));
      nprogs_all += nprogs;
    }
  free (progs);
  progs = NULL;

  if (nprogs_all == 0)
    {
      /* No text instructions – BSS/data-only object.
         Still need to lay out BSS and data symbols so that each BSS
         global gets a unique, non-overlapping offset within the section.
         Without this, every symbol would stay at value 0 and the linker
         would map all of them to the same output address.  */
      long data_total_early = 0, bss_total_early = 0;
      int isym;
      unsigned int osym;

      /* Layout data symbols from ADATA records */
      for (isym = 0; isym < n_int_syms; isym++)
        {
          if (int_syms[isym].stype == P9_SDATA)
            {
              long data_extent = 0;
              int drec;
              for (drec = 0; drec < ndatarecs; drec++)
                {
                  if (datarecs[drec].sym_idx == isym)
                    {
                      long end = datarecs[drec].offset + datarecs[drec].width;
                      if (end > data_extent) data_extent = end;
                    }
                }
              int_syms[isym].value = data_total_early;
              data_total_early += data_extent;
            }
        }

      /* Layout BSS symbols: assign each a unique offset using its size */
      for (isym = 0; isym < n_int_syms; isym++)
        {
          if (int_syms[isym].stype == P9_SBSS)
            {
              int_syms[isym].value = bss_total_early;
              bss_total_early += int_syms[isym].bss_size;
            }
        }

      /* Propagate computed offsets and sections back to tdata->symbols */
      for (osym = 0; osym < tdata->nsyms; osym++)
        {
          const char *sname = tdata->symbols[osym].name;
          for (isym = 0; isym < n_int_syms; isym++)
            if (strcmp (int_syms[isym].name, sname) == 0)
              {
                tdata->symbols[osym].value = (bfd_vma) int_syms[isym].value;
                switch (int_syms[isym].stype)
                  {
                  case P9_SDATA:
                    tdata->symbols[osym].section =
                      bfd_get_section_by_name (abfd, ".data");
                    break;
                  case P9_SBSS:
                    tdata->symbols[osym].section =
                      bfd_get_section_by_name (abfd, ".bss");
                    break;
                  default: break;
                  }
                break;
              }
        }

      tdata->data_size = (bfd_size_type) data_total_early;
      tdata->bss_size  = (bfd_size_type) bss_total_early;
      tdata->encoded   = 1;
      free (datarecs);
      free (progs_all);
      return 1;
    }

  /* ---- Resolve D_BRANCH targets to pcond_idx ---- */
  /* First, assign tentative PCs using max instruction sizes */
  /* We use ADJSP→ADDL/SUBL/NOP conversion like 8l does */
  for (i = 0; i < nprogs_all; i++)
    {
      if (progs_all[i].as == P9AS_ADJSP)
        {
          long v = progs_all[i].from.offset;
          if (v == 0)
            progs_all[i].as = P9AS_NOP;
          else if (v > 0)
            progs_all[i].as = P9AS_SUBL;         /* allocate: SUB from SP */
          else
            {
              progs_all[i].as = P9AS_ADDL;        /* deallocate: ADD to SP */
              progs_all[i].from.offset = -v;
            }
          progs_all[i].to.type   = P9D_SP;
          progs_all[i].to.index  = P9D_NONE;
          progs_all[i].to.scale  = 1;
          progs_all[i].to.offset = 0;
          progs_all[i].to.sym    = -1;
        }
    }

  /* ---- Adjust D_AUTO / D_PARAM offsets by the function auto (frame) size ----
     In Plan 9 .8 object files, D_AUTO (63) and D_PARAM (64) address offsets
     are stack-relative but use different reference points:
       D_AUTO: offset from old_SP (SP at function entry).  Negative offsets
               point into the local variable area.
               After sub $N,%esp: new_SP + (off + N)
               Example: D_AUTO -0x40 with N=0x50 → new_SP+0x10
       D_PARAM: offset from old_SP+4 (first argument, one word above the return
                address pushed by CALL).  Non-negative offsets.
                After sub $N,%esp: new_SP + (off + N + 4)
                Example: D_PARAM 0 with N=0x50 → new_SP+0x54
     After the BFD backend synthesises ADJSP $N (sub $N,%esp), all references
     must be converted to current-SP-relative, matching 9front 8l span().  */
  { long cur_auto_size = 0;
    for (i = 0; i < nprogs_all; i++)
      {
        /* Track function auto/frame size from ATEXT instruction */
        if (progs_all[i].as == P9AS_TEXT)
          {
            cur_auto_size = progs_all[i].to.offset;
            continue;
          }
        /* Skip if no frame: auto_size == 0 means the function has no
           locals and P9AS_TEXT does not inject ADJSP, so no adjustment
           is needed.  Negative values cannot occur (ATEXT auto-size is
           always non-negative in Plan 9 .8 files), but guard anyway.  */
        if (cur_auto_size <= 0)
          continue;

        /* Adjust D_AUTO and D_PARAM offsets (with or without D_INDIR).
           In the x86 calling convention, after CALL pushes a 4-byte return
           address, the first D_PARAM argument is at old_SP+4.  After
           sub $N,%esp (frame allocation), SP-relative offsets are:
             D_AUTO off  → new_SP + (off + auto_size)       (auto: from old_SP)
             D_PARAM off → new_SP + (off + auto_size + 4)   (param: from old_SP+4)
           The extra +4 for D_PARAM accounts for the return address slot.   */
#define P9_ADJOFF(a)                                                          \
        do {                                                                  \
          int _t = (a).type;                                                  \
          if (_t == P9D_AUTO || _t == (P9D_AUTO + P9D_INDIR))                \
            (a).offset += cur_auto_size;                                     \
          else if (_t == P9D_PARAM || _t == (P9D_PARAM + P9D_INDIR))        \
            (a).offset += cur_auto_size + 4;                                 \
          /* D_ADDR with index D_AUTO/D_PARAM (LEA of stack variable) */     \
          if (_t == P9D_ADDR && (a).index == P9D_AUTO)                       \
            (a).offset += cur_auto_size;                                     \
          else if (_t == P9D_ADDR && (a).index == P9D_PARAM)                 \
            (a).offset += cur_auto_size + 4;                                 \
        } while (0)

        P9_ADJOFF (progs_all[i].from);
        P9_ADJOFF (progs_all[i].to);
#undef P9_ADJOFF
      }
  }
  /* We run span up to 20 iterations until stable. */

  /* First pass: size each instruction */
  memset (&ctx, 0, sizeof(ctx));

  c = 0;
  for (i = 0; i < nprogs_all; i++)
    {
      progs_all[i].pc   = c;
      progs_all[i].mark = 0;
      if (progs_all[i].as == P9AS_TEXT)
        {
          /* ATEXT: 0 bytes, just records the function entry PC */
          /* Store the sym index we saved in .pc earlier */
          int si = (int) progs_all[i].pc;
          progs_all[i].pc   = c;   /* restore to byte PC */
          if (si >= 0 && si < n_int_syms)
            int_syms[si].value = c;
          continue;
        }
      ctx.andptr  = ctx.and_buf;
      ctx.cur_pc  = c;
      progs_all[i].pcond_idx = -1;
      /* Initial encoding to get size */
      { int sz = p9_asmins (&ctx, &progs_all[i], progs_all, nprogs_all,
                              int_syms, n_int_syms);
        progs_all[i].mark = (sz < 0) ? 0 : sz;
        c += progs_all[i].mark; }
    }

  /* Now resolve branch targets and iterate */
  /* Resolve D_BRANCH target offsets to indices in progs_all[].
     In Plan 9 .8 files, D_BRANCH.offset is a FUNCTION-RELATIVE instruction
     index where ATEXT itself = 0, the first real instruction = 1, etc.
     It is NOT a byte offset into the encoded text and NOT a file-global
     counter.  We stored this function-relative index in progs_all[j].back
     (reset to 0 at each ATEXT; see the global_plan9_pc reset above),
     so we match target_pc against .back rather than .pc (byte offset).
     Synthetic ADJSP entries have back==-1 and are never branch targets.  */
  for (i = 0; i < nprogs_all; i++)
    {
      if (progs_all[i].to.type == P9D_BRANCH)
        {
          long target_pc = progs_all[i].to.offset;
          int j, best = -1;
          for (j = 0; j < nprogs_all; j++)
            {
              if (progs_all[j].back == target_pc)
                { best = j; break; }
            }
          progs_all[i].pcond_idx = best;
        }
    }

  /* Iterative span (for branch size optimization) */
  for (pass = 0; pass < 20; pass++)
    {
      again = 0;
      c = 0;
      for (i = 0; i < nprogs_all; i++)
        {
          progs_all[i].pc = c;
          if (progs_all[i].as == P9AS_TEXT)
            {
              /* Update sym value to current PC */
              /* The sym_idx was saved before we overwrote .pc;
                 re-find it from int_syms by matching value == previous PC */
              continue;
            }
          if (progs_all[i].to.type == P9D_BRANCH)
            {
              ctx.andptr = ctx.and_buf;
              ctx.cur_pc = c;
              memset (ctx.reloc_syms ? ctx.reloc_syms : (void*)0, 0, 0);
              ctx.n_relocs = 0;
              { int sz = p9_asmins (&ctx, &progs_all[i], progs_all, nprogs_all,
                                     int_syms, n_int_syms);
                if (sz < 0) sz = 0;
                if (sz != progs_all[i].mark)
                  { progs_all[i].mark = sz; again++; } }
            }
          c += progs_all[i].mark;
        }
      if (!again) break;
    }

  /* Final PC assignment */
  text_pc = 0;
  for (i = 0; i < nprogs_all; i++)
    {
      progs_all[i].pc = text_pc;
      if (progs_all[i].as != P9AS_TEXT)
        text_pc += progs_all[i].mark;
    }

  /* Update STEXT symbol values with final PCs */
  for (i = 0; i < nprogs_all; i++)
    {
      if (progs_all[i].as == P9AS_TEXT)
        {
          /* Find which sym this ATEXT belongs to */
          int si;
          long entry_pc = progs_all[i].pc;
          /* Look for next instruction's PC to confirm, but mainly we
             trust that from.sym is the correct symbol index */
          si = progs_all[i].from.sym;
          if (si >= 0 && si < n_int_syms && int_syms[si].stype == P9_STEXT)
            int_syms[si].value = entry_pc;
        }
    }

  /* ---- Layout data symbols ---- */
  { int j;
    for (j = 0; j < n_int_syms; j++)
      {
        if (int_syms[j].stype == P9_SDATA)
          {
            /* compute size from ADATA records */
            long maxend = 0, k;
            for (k = 0; k < ndatarecs; k++)
              {
                if (datarecs[k].sym_idx == j)
                  {
                    long end = datarecs[k].offset + datarecs[k].width;
                    if (end > maxend) maxend = end;
                  }
              }
            int_syms[j].value    = data_total;
            data_total          += maxend;
          }
      }
    /* BSS symbols */
    for (j = 0; j < n_int_syms; j++)
      {
        if (int_syms[j].stype == P9_SBSS)
          {
            int_syms[j].value = bss_total;
            bss_total        += int_syms[j].bss_size;
          }
      }
  }

  /* ---- Allocate output buffers ---- */
  text_buf_cap = (bfd_size_type)(text_pc + 1);
  text_buf = (bfd_byte *) bfd_zalloc (abfd, text_buf_cap);
  if (text_buf == NULL) goto out_err;

  if (data_total > 0)
    {
      data_buf_cap = (bfd_size_type) data_total;
      data_buf = (bfd_byte *) bfd_zalloc (abfd, data_buf_cap);
      /* if alloc fails, data section will just be zeros */
    }

  /* ---- Emit machine code ---- */
  ctx.andptr      = ctx.and_buf;
  ctx.cur_pc      = 0;
  ctx.n_relocs    = 0;
  ctx.reloc_cap   = 0;
  ctx.reloc_syms  = NULL;
  ctx.reloc_offsets = NULL;
  ctx.reloc_pcrls = NULL;

  for (i = 0; i < nprogs_all; i++)
    {
      int sz;
      if (progs_all[i].as == P9AS_TEXT) continue;
      ctx.cur_pc  = progs_all[i].pc;
      sz = p9_asmins (&ctx, &progs_all[i], progs_all, nprogs_all,
                       int_syms, n_int_syms);
      if (sz > 0 && progs_all[i].pc + sz <= (long)text_buf_cap)
        memcpy (text_buf + progs_all[i].pc, ctx.and_buf, (size_t) sz);
    }

  /* ---- Emit data content ---- */
  if (data_buf && data_buf_cap > 0)
    {
      int k;
      for (k = 0; k < ndatarecs; k++)
        {
          int si = datarecs[k].sym_idx;
          long base = int_syms[si].value;
          long off  = datarecs[k].offset;
          int  w    = datarecs[k].width;
          long absoff = base + off;
          if (absoff < 0 || absoff + w > (long)data_buf_cap) continue;
          if (!datarecs[k].is_sym_ref)
            {
              long v = datarecs[k].val.ival;
              switch (w)
                {
                case 1: data_buf[absoff] = (unsigned char)v; break;
                case 2: data_buf[absoff]   = (unsigned char)v;
                        data_buf[absoff+1] = (unsigned char)(v>>8); break;
                case 4: data_buf[absoff]   = (unsigned char)v;
                        data_buf[absoff+1] = (unsigned char)(v>>8);
                        data_buf[absoff+2] = (unsigned char)(v>>16);
                        data_buf[absoff+3] = (unsigned char)(v>>24); break;
                case 8: { unsigned long lo = (unsigned long)v;
                          int bi;
                          for (bi=0; bi<8 && bi<w; bi++)
                            data_buf[absoff+bi] = (unsigned char)(lo >> (bi*8));
                          break; }
                }
            }
          /* sym ref: leave as 0, reloc will fix it */
        }
    }

  /* ---- Build relocation arrays from ctx ---- */
  if (ctx.n_relocs > 0)
    {
      struct plan9_out_i386_reloc *rel =
        (struct plan9_out_i386_reloc *)bfd_alloc (
          abfd, ctx.n_relocs * sizeof(struct plan9_out_i386_reloc));
      if (rel)
        {
          /* Map internal sym indices to tdata->symbols indices */
          int r;
          for (r = 0; r < ctx.n_relocs; r++)
            {
              int  isi  = ctx.reloc_syms[r];
              int  bsym = -1;
              unsigned int q;
              /* Find the asymbol in tdata->symbols that matches int_syms[isi] */
              if (isi >= 0 && isi < n_int_syms)
                for (q = 0; q < tdata->nsyms; q++)
                  if (strcmp (tdata->symbols[q].name,
                               int_syms[isi].name) == 0)
                    { bsym = (int) q; break; }
              rel[r].section_offset = ctx.reloc_offsets[r];
              rel[r].sym_idx        = bsym;
              rel[r].pc_relative    = ctx.reloc_pcrls[r];
            }
          tdata->text_relocs  = rel;
          tdata->text_nrelocs = ctx.n_relocs;
        }
    }

  /* ---- Update tdata->symbols with correct values ---- */
  { unsigned int q;
    for (q = 0; q < tdata->nsyms; q++)
      {
        const char *sname = tdata->symbols[q].name;
        int j;
        for (j = 0; j < n_int_syms; j++)
          if (strcmp (int_syms[j].name, sname) == 0)
            {
              tdata->symbols[q].value = (bfd_vma) int_syms[j].value;
              /* Update section */
              switch (int_syms[j].stype)
                {
                case P9_STEXT:
                  tdata->symbols[q].section =
                    bfd_get_section_by_name (abfd, ".text");
                  break;
                case P9_SDATA:
                  tdata->symbols[q].section =
                    bfd_get_section_by_name (abfd, ".data");
                  break;
                case P9_SBSS:
                  tdata->symbols[q].section =
                    bfd_get_section_by_name (abfd, ".bss");
                  break;
                default: break;
                }
              break;
            }
      }
  }

  /* ---- Store results in tdata ---- */
  tdata->text_content = text_buf;
  tdata->text_size    = (bfd_size_type) text_pc;
  tdata->data_content = data_buf;
  tdata->data_size    = (bfd_size_type) data_total;
  tdata->bss_size     = (bfd_size_type) bss_total;
  tdata->encoded      = 1;

  /* Cleanup */
  free (ctx.reloc_syms);
  free (ctx.reloc_offsets);
  free (ctx.reloc_pcrls);
  free (datarecs);
  free (progs_all);
  return 1;

out_err:
  if (buf)       free (buf);
  if (progs)     free (progs);
  if (progs_all) free (progs_all);
  if (datarecs)  free (datarecs);
  if (ctx.reloc_syms)    free (ctx.reloc_syms);
  if (ctx.reloc_offsets) free (ctx.reloc_offsets);
  if (ctx.reloc_pcrls)   free (ctx.reloc_pcrls);
  return 0;
}



static bfd_boolean
plan9_out_i386_mkobject (bfd *abfd)
{
  struct plan9_out_i386_tdata *tdata;

  tdata = (struct plan9_out_i386_tdata *) bfd_zalloc (
    abfd, sizeof (struct plan9_out_i386_tdata));
  if (tdata == NULL)
    return FALSE;

  abfd->tdata.any = tdata;
  return TRUE;
}

/* Recognise a Plan 9 i386 object file.
   The heuristic matches 9front's isobjfile(): read 5 bytes and check
   that bytes [3]==1 && bytes[4]=='<' (with bytes[0:1] == ANAME opcode).  */

static const bfd_target *
plan9_out_i386_object_p (bfd *abfd)
{
  unsigned char buf[5];
  asection *text_sec, *data_sec, *bss_sec;
  struct plan9_out_i386_tdata *tdata;

  if (bfd_seek (abfd, 0, SEEK_SET) != 0)
    return NULL;

  if (bfd_bread (buf, 5, abfd) != 5)
    {
      bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  /* Validate the ANAME opcode and the isobjfile heuristic from 9front.
     9front's isobjfile() reads 5 bytes and checks:
       buf[2]==1 && buf[3]=='<'  (older: 1-byte opcode, sym_idx=1, name starts '<')
     OR
       buf[3]==1 && buf[4]=='<'  (i386: 2-byte opcode=0x007e, sym_idx=1, name starts '<')

     For i386 .8 files the opcode is always 0x007e (ANAME=126 LE), so bytes 0-1
     must be 0x7e,0x00.  Bytes 3-4 check that the first ANAME record has symbol
     index 1 and a name beginning with '<' (Plan 9 file-history path segment).
     The alternative (buf[2]==1, buf[3]=='<') also requires opcode 0x007e, so it
     would fire only if the type byte at [2] happened to be 1 – very unlikely for
     real i386 .8 files, but kept for symmetry with isobjfile().  */
  if (!(buf[0] == 0x7e && buf[1] == 0x00
        && ((buf[3] == 1 && buf[4] == '<')
            || (buf[2] == 1 && buf[3] == '<'))))
    {
      bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  /* Set architecture */
  if (!bfd_default_set_arch_mach (abfd, bfd_arch_i386, 0))
    return NULL;

  /* Allocate private data */
  tdata = (struct plan9_out_i386_tdata *) bfd_zalloc (
    abfd, sizeof (struct plan9_out_i386_tdata));
  if (tdata == NULL)
    return NULL;
  abfd->tdata.any = tdata;

  /* Create .text, .data, .bss sections with nominal sizes.
     Actual content is the instruction stream (we don't decode it here).  */
  text_sec = bfd_make_section (abfd, ".text");
  if (text_sec == NULL)
    return NULL;
  text_sec->flags = SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS;
  text_sec->vma   = 0;
  text_sec->size  = 0;

  data_sec = bfd_make_section (abfd, ".data");
  if (data_sec == NULL)
    return NULL;
  data_sec->flags = SEC_ALLOC | SEC_LOAD | SEC_DATA | SEC_HAS_CONTENTS;
  data_sec->vma   = 0;
  data_sec->size  = 0;

  bss_sec = bfd_make_section (abfd, ".bss");
  if (bss_sec == NULL)
    return NULL;
  bss_sec->flags = SEC_ALLOC;
  bss_sec->vma   = 0;
  bss_sec->size  = 0;

  abfd->flags = HAS_SYMS | HAS_RELOC;

  /* Phase 2: encode the .8 Prog stream to generate actual machine
     code, compute section sizes and collect relocations.  */
  p9_init_optab ();
  p9_init_tables ();
  if (p9obj_encode_file (abfd, text_sec, data_sec, bss_sec))
    {
      struct plan9_out_i386_tdata *td2 = plan9_out_i386_tdata (abfd);
      text_sec->size = td2->text_size;
      data_sec->size = td2->data_size;
      bss_sec->size  = td2->bss_size;
      /* Flag contents as present (size > 0 sections) */
      if (td2->text_size == 0) text_sec->flags &= ~SEC_HAS_CONTENTS;
      if (td2->data_size == 0) data_sec->flags &= ~SEC_HAS_CONTENTS;
      /* Mark sections with relocations */
      if (td2->text_nrelocs > 0)
        {
          text_sec->flags |= SEC_RELOC;
          text_sec->reloc_count = td2->text_nrelocs;
        }
      if (td2->data_nrelocs > 0)
        {
          data_sec->flags |= SEC_RELOC;
          data_sec->reloc_count = td2->data_nrelocs;
        }
    }

  return abfd->xvec;
}

/* ---- get_section_contents: return pre-generated machine code ------- */
static bfd_boolean
plan9_out_i386_get_section_contents (bfd *abfd, asection *sec,
                                     void *loc, file_ptr off,
                                     bfd_size_type sz)
{
  struct plan9_out_i386_tdata *td = plan9_out_i386_tdata (abfd);
  const bfd_byte *src = NULL;
  bfd_size_type   src_sz = 0;

  if (strcmp (sec->name, ".text") == 0)
    { src = td->text_content; src_sz = td->text_size; }
  else if (strcmp (sec->name, ".data") == 0)
    { src = td->data_content; src_sz = td->data_size; }

  if (src == NULL || src_sz == 0)
    {
      if (sz == 0) return TRUE;
      memset (loc, 0, (size_t) sz);
      return TRUE;
    }

  if ((bfd_size_type) off >= src_sz)
    return FALSE;
  if ((bfd_size_type) off + sz > src_sz)
    sz = src_sz - (bfd_size_type) off;
  memcpy (loc, src + off, (size_t) sz);
  return TRUE;
}

/* ---- Reloc howto table -------------------------------------------- */
static reloc_howto_type plan9_out_i386_howto_table[] =
{
  /* 0 – absolute 32-bit */
  HOWTO (0, 0, 2, 32, FALSE, 0, complain_overflow_dont,
         NULL, "ABS32", FALSE, 0, 0xffffffff, FALSE),
  /* 1 – PC-relative 32-bit (call/jmp).
     pcrel_offset=TRUE: BFD subtracts r->address from the relocation so the
     field gets  disp32 = sym_VMA + addend - (sec_VMA + output_offset + r->addr).
     addend=-4 then produces the correct x86 displacement
       disp32 = sym_VMA - next_IP  (next_IP = field_VMA + 4).  */
  HOWTO (1, 0, 2, 32, TRUE,  0, complain_overflow_dont,
         NULL, "PC32",  FALSE, 0, 0xffffffff, TRUE),
};

static reloc_howto_type *
plan9_out_i386_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                   bfd_reloc_code_real_type code)
{
  switch (code)
    {
    case BFD_RELOC_32:       return &plan9_out_i386_howto_table[0];
    case BFD_RELOC_32_PCREL: return &plan9_out_i386_howto_table[1];
    default: return NULL;
    }
}

static long
plan9_out_i386_get_reloc_upper_bound (bfd *abfd, asection *sec)
{
  struct plan9_out_i386_tdata *td = plan9_out_i386_tdata (abfd);
  if (strcmp (sec->name, ".text") == 0)
    return (long) ((td->text_nrelocs + 1) * sizeof (arelent *));
  if (strcmp (sec->name, ".data") == 0)
    return (long) ((td->data_nrelocs + 1) * sizeof (arelent *));
  return (long) sizeof (arelent *);
}

static long
plan9_out_i386_canonicalize_reloc (bfd *abfd, asection *sec,
                                    arelent **relpp, asymbol **syms ATTRIBUTE_UNUSED)
{
  struct plan9_out_i386_tdata *td;
  struct plan9_out_i386_reloc *recs = NULL;
  unsigned int n = 0, i;

  /* Ensure sym_ptrs[] is populated so we can build arelent.sym_ptr_ptr.  */
  if (!p9obj_slurp_symtab (abfd))
    { relpp[0] = NULL; return 0; }

  td = plan9_out_i386_tdata (abfd);

  if (strcmp (sec->name, ".text") == 0)
    { recs = td->text_relocs; n = td->text_nrelocs; }
  else if (strcmp (sec->name, ".data") == 0)
    { recs = td->data_relocs; n = td->data_nrelocs; }

  if (recs == NULL || n == 0)
    { relpp[0] = NULL; return 0; }

  for (i = 0; i < n; i++)
    {
      arelent *r = (arelent *) bfd_zalloc (abfd, sizeof (arelent));
      if (r == NULL) { relpp[i] = NULL; return (long) i; }

      /* sym_ptr_ptr: pointer into sym_ptrs[] array (standard BFD convention) */
      if (recs[i].sym_idx >= 0 && (unsigned)recs[i].sym_idx < td->nsyms
          && td->sym_ptrs != NULL)
        r->sym_ptr_ptr = &td->sym_ptrs[recs[i].sym_idx];
      else
        { relpp[i] = NULL; continue; }
      r->address     = (bfd_vma) recs[i].section_offset;
      /* For x86 PC-relative CALL/JMP rel32, the x86 CPU computes:
           target = next_IP + disp32
                  = (field_VMA + 4) + disp32
         so the correct displacement is: disp32 = sym_VMA - next_IP.
         BFD's reloc formula with pcrel_offset=TRUE (our PC32 howto) is:
           field = sym_VMA + addend - (sec_VMA + output_offset + r->address)
                 = sym_VMA + addend - field_VMA
         CPU target = field_VMA + 4 + field
                    = field_VMA + 4 + sym_VMA + addend - field_VMA
                    = sym_VMA + addend + 4
         Setting addend = -4 lands exactly at sym_VMA.
         Absolute (non-PC-relative) relocations use addend = 0.  */
      r->addend      = recs[i].pc_relative ? -4 : 0;
      r->howto       = &plan9_out_i386_howto_table[recs[i].pc_relative ? 1 : 0];
      relpp[i] = r;
    }
  relpp[n] = NULL;
  return (long) n;
}

/* Return the upper bound on the symbol table size (in bytes of pointers).  */
static long
plan9_out_i386_get_symtab_upper_bound (bfd *abfd)
{
  if (!p9obj_slurp_symtab (abfd))
    return -1;
  return (long) ((bfd_get_symcount (abfd) + 1) * sizeof (asymbol *));
}

/* Fill in the symbol table.  Returns the number of symbols.  */
static long
plan9_out_i386_canonicalize_symtab (bfd *abfd, asymbol **location)
{
  struct plan9_out_i386_tdata *tdata;
  unsigned int i;

  if (!p9obj_slurp_symtab (abfd))
    return -1;

  tdata = plan9_out_i386_tdata (abfd);
  for (i = 0; i < tdata->nsyms; i++)
    location[i] = &tdata->symbols[i];
  location[tdata->nsyms] = NULL;

  return (long) tdata->nsyms;
}

static void
plan9_out_i386_get_symbol_info (bfd *abfd ATTRIBUTE_UNUSED,
                                 asymbol *symbol,
                                 symbol_info *ret)
{
  bfd_symbol_info (symbol, ret);
}

/* Stub: sizeof_headers returns 0 for object files.  */
static int
p9out_sizeof_headers (bfd *abfd ATTRIBUTE_UNUSED,
                      bfd_boolean exec ATTRIBUTE_UNUSED)
{
  return 0;
}

/* Stub: set_section_contents (no-op for read-only backend).  */
static bfd_boolean
p9out_set_section_contents (bfd *abfd ATTRIBUTE_UNUSED,
                             asection *sec ATTRIBUTE_UNUSED,
                             const void *data ATTRIBUTE_UNUSED,
                             file_ptr off ATTRIBUTE_UNUSED,
                             bfd_size_type sz ATTRIBUTE_UNUSED)
{
  return TRUE;
}

/* --------------------------------------------------------------------- */
/* Macro stubs following the BFD NAME##_xxx naming convention.
   These are expanded by BFD_JUMP_TABLE_xxx macros in the bfd_target.  */

/* BFD_JUMP_TABLE_GENERIC */
#define p9out_close_and_cleanup            _bfd_generic_close_and_cleanup
#define p9out_bfd_free_cached_info         _bfd_generic_bfd_free_cached_info
#define p9out_new_section_hook             _bfd_generic_new_section_hook
#define p9out_get_section_contents         plan9_out_i386_get_section_contents
#define p9out_get_section_contents_in_window \
  _bfd_generic_get_section_contents_in_window

/* BFD_JUMP_TABLE_SYMBOLS */
#define p9out_get_symtab_upper_bound       plan9_out_i386_get_symtab_upper_bound
#define p9out_canonicalize_symtab          plan9_out_i386_canonicalize_symtab
#define p9out_make_empty_symbol            _bfd_generic_make_empty_symbol
#define p9out_print_symbol                 _bfd_nosymbols_print_symbol
#define p9out_get_symbol_info              plan9_out_i386_get_symbol_info
#define p9out_bfd_is_local_label_name      bfd_generic_is_local_label_name
#define p9out_bfd_is_target_special_symbol \
  ((bfd_boolean (*) (bfd *, asymbol *)) bfd_false)
#define p9out_get_lineno                   _bfd_nosymbols_get_lineno
#define p9out_find_nearest_line            _bfd_nosymbols_find_nearest_line
#define p9out_find_inliner_info            _bfd_nosymbols_find_inliner_info
#define p9out_bfd_make_debug_symbol        _bfd_nosymbols_bfd_make_debug_symbol
#define p9out_read_minisymbols             _bfd_generic_read_minisymbols
#define p9out_minisymbol_to_symbol         _bfd_generic_minisymbol_to_symbol

/* BFD_JUMP_TABLE_RELOCS */
#define p9out_get_reloc_upper_bound        plan9_out_i386_get_reloc_upper_bound
#define p9out_canonicalize_reloc           plan9_out_i386_canonicalize_reloc
#define p9out_bfd_reloc_type_lookup        plan9_out_i386_reloc_type_lookup

/* BFD_JUMP_TABLE_WRITE */
#define p9out_set_arch_mach                _bfd_generic_set_arch_mach
/* p9out_set_section_contents defined above */

/* BFD_JUMP_TABLE_LINK */
/* p9out_sizeof_headers defined above */
#define p9out_bfd_get_relocated_section_contents \
  bfd_generic_get_relocated_section_contents
#define p9out_bfd_relax_section            bfd_generic_relax_section
#define p9out_bfd_link_hash_table_create   _bfd_generic_link_hash_table_create
#define p9out_bfd_link_hash_table_free     _bfd_generic_link_hash_table_free
#define p9out_bfd_link_add_symbols         _bfd_generic_link_add_symbols
#define p9out_bfd_link_just_syms           _bfd_generic_link_just_syms
#define p9out_bfd_final_link               _bfd_generic_final_link
#define p9out_bfd_link_split_section       _bfd_generic_link_split_section
#define p9out_bfd_gc_sections              bfd_generic_gc_sections
#define p9out_bfd_merge_sections           bfd_generic_merge_sections
#define p9out_bfd_is_group_section         bfd_generic_is_group_section
#define p9out_bfd_discard_group            bfd_generic_discard_group
#define p9out_section_already_linked       _bfd_generic_section_already_linked

/* --------------------------------------------------------------------- */
/* The bfd_target vector                                                   */

/* Suppress GCC 8+ warnings about casting bfd_true/bfd_false to specific
   function pointer types in the BFD_JUMP_TABLE_* macros from libbfd.h.
   These casts are pre-existing in the BFD infrastructure.  */
#if defined(__GNUC__) && __GNUC__ >= 8
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-function-type"
#endif

const bfd_target plan9_out_i386_vec =
{
  "plan9-out-i386",             /* name */
  bfd_target_unknown_flavour,   /* flavour (not a.out / COFF / ELF) */
  BFD_ENDIAN_LITTLE,            /* target byte order */
  BFD_ENDIAN_LITTLE,            /* target header byte order */
  (HAS_RELOC | HAS_SYMS),       /* object flags */
  (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_DATA | SEC_HAS_CONTENTS),
  0,                            /* symbol_leading_char */
  ' ',                          /* ar_pad_char */
  15,                           /* ar_max_namelen */

  /* data accessors (little-endian i386) */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
  bfd_getl32, bfd_getl_signed_32, bfd_putl32,
  bfd_getl16, bfd_getl_signed_16, bfd_putl16,

  /* header accessors (little-endian) */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
  bfd_getl32, bfd_getl_signed_32, bfd_putl32,
  bfd_getl16, bfd_getl_signed_16, bfd_putl16,

  {                             /* bfd_check_format */
    _bfd_dummy_target,          /* core */
    plan9_out_i386_object_p,    /* object */
    _bfd_dummy_target,          /* archive */
    _bfd_dummy_target,          /* _dummy (unknown) */
  },
  {                             /* bfd_set_format */
    bfd_false,
    plan9_out_i386_mkobject,
    bfd_false,
    bfd_false,
  },
  {                             /* bfd_write_contents */
    bfd_false,
    bfd_true,
    bfd_false,
    bfd_false,
  },

  BFD_JUMP_TABLE_GENERIC (p9out),
  BFD_JUMP_TABLE_COPY (_bfd_generic),
  BFD_JUMP_TABLE_CORE (_bfd_nocore),
  BFD_JUMP_TABLE_ARCHIVE (_bfd_noarchive),
  BFD_JUMP_TABLE_SYMBOLS (p9out),
  BFD_JUMP_TABLE_RELOCS (p9out),
  BFD_JUMP_TABLE_WRITE (p9out),
  BFD_JUMP_TABLE_LINK (p9out),
  BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

  NULL,   /* alternative_target */
  NULL    /* backend_data */
};

#if defined(__GNUC__) && __GNUC__ >= 8
# pragma GCC diagnostic pop
#endif
