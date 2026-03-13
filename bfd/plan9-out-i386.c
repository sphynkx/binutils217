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
              /* Update section in found_syms for this sym_idx */
              for (i2 = 0; i2 < nsyms_found; i2++)
                {
                  if (found_syms[i2].idx == (unsigned int) sym_idx)
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

  return abfd->xvec;
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
#define p9out_get_section_contents         _bfd_generic_get_section_contents
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
#define p9out_get_reloc_upper_bound \
  ((long (*) (bfd *, asection *)) bfd_0l)
#define p9out_canonicalize_reloc \
  ((long (*) (bfd *, asection *, arelent **, asymbol **)) bfd_0l)
#define p9out_bfd_reloc_type_lookup        _bfd_norelocs_bfd_reloc_type_lookup

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
