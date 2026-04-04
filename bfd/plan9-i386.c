/* BFD back-end for Plan 9 386 binaries.
   Copyright (C) 1990, 91, 92, 94, 95, 96, 1998 Free Software Foundation, Inc.

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
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */


#define	BYTES_IN_WORD	4
#undef TARGET_IS_BIG_ENDIAN_P

#define	TARGET_PAGE_SIZE	4096
#define	SEGMENT_SIZE	TARGET_PAGE_SIZE

#define	DEFAULT_ARCH	bfd_arch_i386
#define	DEFAULT_MID 	M_386

#define TARGETNAME "plan9-i386"

/* Avoid macro name collisions with other headers.  */
/* aout-target.h expects a macro MY(x) that prefixes symbols for this backend. */
#undef CAT
#undef MY
#define P9_CAT(a,b) a##b
#define MY(OP) P9_CAT(plan9_i386_, OP)


/* This is the normal load address for executables.  */
#define TEXT_START_ADDR		TARGET_PAGE_SIZE

/* see include/aout/aout64.h; neither value describes Plan 9 exactly  */
#define N_HEADER_IN_TEXT(x)	1

/* Determine if this is a shared library.  */
#define N_SHARED_LIB(x) 	0

#define	_MAGIC(b)	((((4*b)+0)*b)+7)
#define	I_MAGIC		_MAGIC(11)	/* intel 386 */
#define	QMAGIC I_MAGIC	/* fake out aout macros */



#include "bfd.h"
#include "sysdep.h"
#include "libbfd.h"
#include "libaout.h"
#include "aout/aout64.h"





/* Binutils 2.17 uses bfd_boolean and TRUE/FALSE.  */
#define boolean bfd_boolean
#ifndef true
# define true TRUE
#endif
#ifndef false
# define false FALSE
#endif

#define MY_symbol_leading_char '\0'

#define MY_BFD_TARGET
#define MY_object_p plan9_i386_object_p
#define MY_write_object_contents plan9_i386_write_object_contents
#define MY_get_symtab_upper_bound plan9_i386_get_symtab_upper_bound
#define MY_canonicalize_symtab plan9_i386_canonicalize_symtab






/* Start of symbols hook addition */
#define MY_get_symbol_info plan9_i386_get_symbol_info
#define MY_make_empty_symbol plan9_i386_make_empty_symbol
#define MY_read_minisymbols _bfd_generic_read_minisymbols
#define MY_minisymbol_to_symbol _bfd_generic_minisymbol_to_symbol
#define MY_read_minisymbols plan9_i386_read_minisymbols
#define MY_minisymbol_to_symbol plan9_i386_minisymbol_to_symbol



asymbol *
plan9_i386_make_empty_symbol (bfd *abfd)
{
	aout_symbol_type *sym;

	// Very noisy - disabled.
	//fprintf (stderr, "DBG P9 MAKE_EMPTY_SYMBOL\n");

	sym = (aout_symbol_type *) bfd_zalloc (abfd, sizeof (aout_symbol_type));
	if (sym == NULL)
		return NULL;

	sym->symbol.the_bfd = abfd;
	return &sym->symbol;
}


void
plan9_i386_get_symbol_info (bfd *abfd, asymbol *symbol, symbol_info *ret)
{
	// Very noisy - disabled.
	//fprintf (stderr, "DBG P9 GET_SYMBOL_INFO: %s\n",
	//	 symbol && symbol->name ? symbol->name : "(null)");
	bfd_symbol_info (symbol, ret);
}

/* End of symbols hook addition */






static void plan9_swap_exec_header_out (bfd *abfd,
                                        const struct internal_exec *execp,
                                        struct external_exec *ext);

/* Plan 9 uses static linking; ignore dynamic-link related hooks.  */

/*
static bfd_boolean
MY (add_one_symbol) (struct bfd_link_info *info,
                     struct aout_link_hash_entry *h,
                     const char *name,
                     flagword flags,
                     asection *section,
                     bfd_vma value,
                     bfd_boolean copy,
                     bfd_boolean collect,
                     struct bfd_link_hash_entry **hashp)
{
  (void) info; (void) h; (void) name; (void) flags; (void) section;
  (void) value; (void) copy; (void) collect; (void) hashp;
  return TRUE;
}
*/


static bfd_boolean
MY (write_dynamic_symbol) (bfd *output_bfd,
                           struct bfd_link_info *info,
                           struct aout_link_hash_entry *h)
{
  (void) output_bfd; (void) info; (void) h;
  return TRUE;
}

static bfd_boolean
MY (finish_dynamic_link) (bfd *output_bfd, struct bfd_link_info *info)
{
  (void) output_bfd; (void) info;
  return TRUE;
}


/* Plan 9-specific archive symbol-table reader.
   9front archives use the standard !<arch> magic but the __.SYMDEF
   member stores (fileoffset, symname) pairs that are not compatible
   with the BSD (count, (nameoff,fileoff)*, strings) layout expected
   by bfd_slurp_bsd_armap.  We skip the SYMDEF member so that the
   archive container is recognised successfully.  The linker scans
   all members to resolve undefined references (bfd_has_map = FALSE).  */

static bfd_boolean
plan9_i386_slurp_armap (bfd *abfd)
{
  char nextname[17];
  struct areltdata *mapdata;
  file_ptr newpos;

  /* Peek at the first 16 bytes (the ar_name field of the first member). */
  if (bfd_bread (nextname, 16, abfd) != 16)
    {
      bfd_has_map (abfd) = FALSE;
      return TRUE;   /* empty archive */
    }
  nextname[16] = '\0';

  if (bfd_seek (abfd, (file_ptr) -16, SEEK_CUR) != 0)
    return FALSE;

  /* If the first member is a SYMDEF, skip it without parsing its
     content (Plan 9 SYMDEF format is not BSD-compatible).  */
  if (strncmp (nextname, "__.SYMDEF       ", 16) == 0
      || strncmp (nextname, "__.SYMDEF/      ", 16) == 0
      || strncmp (nextname, "SYMDEF          ", 16) == 0)
    {
      mapdata = (struct areltdata *) _bfd_read_ar_hdr (abfd);
      if (mapdata == NULL)
        {
          /* Header unreadable -- treat this as wrong format.  */
          bfd_set_error (bfd_error_wrong_format);
          return FALSE;
        }

      /* Skip the SYMDEF content and align to even boundary.  */
      newpos = bfd_tell (abfd) + (file_ptr) mapdata->parsed_size;
      if (newpos & 1)
        newpos++;
      bfd_release (abfd, mapdata);

      if (bfd_seek (abfd, newpos, SEEK_SET) != 0)
        return FALSE;

      bfd_ardata (abfd)->first_file_filepos = newpos;
    }

  /* No symbol map: the linker will scan all members.  */
  bfd_has_map (abfd) = FALSE;
  return TRUE;
}

#define MY_slurp_armap plan9_i386_slurp_armap

#define	N_BADMAG(x) (N_MAGIC(x) != QMAGIC && N_MAGIC(x) != OMAGIC)
#define	MY_backend_data &MY(backend_data)

#undef N_SYMOFF
#define N_SYMOFF(x)	( N_MAGIC(x) == QMAGIC ? N_DATOFF(x) + (x).a_data : N_DRELOFF(x) + (x).a_drsize )





/* New hooks additions (till include of aout-target.h) */



/* Start reloc hooks additions */

static void
MY (fixup_section_symbol_reloc) (bfd *abfd, arelent *rel)
{
  asymbol *sym;

  if (rel == NULL || rel->howto == NULL || rel->sym_ptr_ptr == NULL)
    return;
  if (*(rel->sym_ptr_ptr) == NULL)
    return;

  sym = *(rel->sym_ptr_ptr);

  /* Plan 9 i386: absolute relocs against local section symbols (.data/.bss)
     come back from generic a.out decode with addend biased by section VMA.
     Undo that bias here.  */
  if (!rel->howto->pc_relative)
    {
      if (sym->section == obj_datasec (abfd))
        rel->addend += obj_datasec (abfd)->vma;
      else if (sym->section == obj_bsssec (abfd))
        rel->addend += obj_bsssec (abfd)->vma;
    }
}

static long
MY (canonicalize_reloc) (bfd *abfd,
                         asection *section,
                         arelent **relptr,
                         asymbol **symbols)
{
  long count;
  long i;

  count = NAME (aout, canonicalize_reloc) (abfd, section, relptr, symbols);
  if (count <= 0)
    return count;

  for (i = 0; i < count; i++)
    {
      arelent *rel = relptr[i];

      if (rel == NULL || rel->howto == NULL || rel->sym_ptr_ptr == NULL)
        continue;
      if (*(rel->sym_ptr_ptr) == NULL)
        continue;

      MY (fixup_section_symbol_reloc) (abfd, rel);
    }

  return count;
}
#define MY_canonicalize_reloc MY(canonicalize_reloc)



/* // 2DEL - not working in process
static void
MY (relocatable_reloc) (reloc_howto_type *howto,
                        bfd *output_bfd,
                        arelent *rel,
                        bfd_vma relocation,
                        bfd_vma r_addr)
{
  asymbol *sym;

  (void) relocation;
  (void) r_addr;

  if (rel == NULL || rel->sym_ptr_ptr == NULL)
    return;
  if (*(rel->sym_ptr_ptr) == NULL)
    return;

  sym = *(rel->sym_ptr_ptr);

#ifdef DEBUG_PLAN9
  fprintf (stderr,
           "DBG PLAN9 RELOCATABLE_RELOC before: addr=%#lx addend=%#lx sym=%s flags=%#lx pc=%d size=%d\n",
           (unsigned long) rel->address,
           (unsigned long) rel->addend,
           sym->name ? sym->name : "(null)",
           (unsigned long) sym->flags,
           howto ? (int) howto->pc_relative : -1,
           howto ? (int) howto->size : -1);
#endif

  / * Plan 9 i386 fix:
     section-symbol absolute relocs against .data/.bss carry an addend
     biased by section VMA (e.g. .data-0x40).  Undo that before final
     relocation is written/applied. * /
  if (howto != NULL
      && !howto->pc_relative
      && sym->section == obj_datasec (output_bfd))
    {
      rel->addend += obj_datasec (output_bfd)->vma;
#ifdef DEBUG_PLAN9
      fprintf (stderr,
               "DBG PLAN9 RELOCATABLE_RELOC after : addr=%#lx addend=%#lx sym=.data datavma=%#lx\n",
               (unsigned long) rel->address,
               (unsigned long) rel->addend,
               (unsigned long) obj_datasec (output_bfd)->vma);
#endif
    }
  else if (howto != NULL
           && !howto->pc_relative
           && sym->section == obj_bsssec (output_bfd))
    {
      rel->addend += obj_bsssec (output_bfd)->vma;
#ifdef DEBUG_PLAN9
      fprintf (stderr,
               "DBG PLAN9 RELOCATABLE_RELOC after : addr=%#lx addend=%#lx sym=.bss bssvma=%#lx\n",
               (unsigned long) rel->address,
               (unsigned long) rel->addend,
               (unsigned long) obj_bsssec (output_bfd)->vma);
#endif
    }
}
#define MY_relocatable_reloc MY(relocatable_reloc)
*/


/*
static bfd_vma
MY (section_reloc_base) (bfd *input_bfd, asection *input_section, asection *section, int r_pcrel)
{
  bfd_vma relocation;

  relocation = (section->output_section->vma
                + section->output_offset
                - section->vma);

  if (r_pcrel)
    relocation += input_section->vma;

  return relocation;
}

static bfd_vma
MY (section_reloc_addend) (bfd *input_bfd, asection *section)
{
  if (section == obj_datasec (input_bfd))
    return obj_datasec (input_bfd)->vma;
  if (section == obj_bsssec (input_bfd))
    return obj_bsssec (input_bfd)->vma;
  return 0;
}
*/
/* END reloc hooks additions */

/*start add1 */
static bfd_boolean MY (bfd_final_link) (bfd *abfd,
					struct bfd_link_info *info);

#define MY_bfd_final_link MY (bfd_final_link)
/*end add1 */
#include "aout-target.h"
#include "safe-ctype.h"
#include "aoutx-plan9-i386.h"

/*start add2 */
bfd_boolean MY (final_link) (bfd *abfd,
			     struct bfd_link_info *info,
			     void (*callback) (bfd *, file_ptr *, file_ptr *, file_ptr *));

static bfd_boolean
MY (bfd_final_link) (bfd *abfd, struct bfd_link_info *info)
{
  return MY (final_link) (abfd, info, MY_final_link_callback);
}
/*end add2 */

static CONST struct aout_backend_data MY(backend_data) = {
	0,	/* zmagic_contiguous */
	1,	/* text_includes_header */
	0,	/* entry_is_text_address */
	0,	/* exec_hdr_flags */
	0x1000,	/* default_text_vma: with text_includes_header=1, text VMA
		   = default_text_vma + EXEC_BYTES_SIZE = 0x1000 + 32 = 0x1020 */
	MY_set_sizes,
	0,	/* exec_header_not_counted */
	0,	/* add_dynamic_symbols */
	0/*MY(add_one_symbol)*/, /* add_one_symbol (use generic) */
	0,	/* link_dynamic_object */
	MY(write_dynamic_symbol),
	0,	/* check_dynamic_reloc */
	MY(finish_dynamic_link),
};

/* Write an object file.
   Section contents have already been written.  We write the
   file header only. */

static boolean
MY(write_object_contents) (bfd *abfd)
/*
     bfd *abfd;
*/
{
	struct external_exec exec_bytes;
	struct internal_exec *execp = exec_hdr (abfd);
	bfd_size_type text_size;
	file_ptr text_end;





	/*
		We must make certain that the magic number has been set.  This
		will normally have been done by set_section_contents, but only if
		there actually are some section contents.
	*/
	if (! abfd->output_has_begun)
		NAME(aout,adjust_sizes_and_vmas) (abfd, &text_size, &text_end);

  /* When producing a new Plan 9 executable via objcopy/strip, the generic
     a.out copying code may "pack" VMAs starting at 0 (text=0, data=text_size).
     Restore Plan 9 VMAs before writing the header/contents.  */
  if (bfd_get_arch (abfd) == bfd_arch_i386
      && bfd_get_start_address (abfd) == 0x1020
      && obj_textsec (abfd) != NULL
      && obj_datasec (abfd) != NULL
      && obj_bsssec (abfd) != NULL
      && obj_textsec (abfd)->vma == 0)
    {
      bfd_vma text_vma, data_vma, bss_vma;

      /* Plan 9 kernel maps text at TEXTADDR+EXEC_BYTES_SIZE = 0x1020 and
	 data at TEXTADDR + a_text = 0x1020 + text_code_size (no page gap).  */
      text_vma = (bfd_vma) TEXT_START_ADDR + EXEC_BYTES_SIZE;
      data_vma = text_vma + obj_textsec (abfd)->size;
      bss_vma  = data_vma + obj_datasec (abfd)->size;

      obj_textsec (abfd)->vma = text_vma;
      obj_datasec (abfd)->vma = data_vma;
      obj_bsssec (abfd)->vma  = bss_vma;
    }


/*
	if(adata(abfd).magic == o_magic) {
		obj_reloc_entry_size (abfd) = RELOC_STD_SIZE;
		WRITE_HEADERS(abfd, execp);
		return true;
	}
*/
	  if (adata (abfd).magic == o_magic)
		{
		  /* If we are writing a relocatable object (as does), use the generic
			 a.out header writer.  The Plan 9 exec writer path (0x1eb) is only
			 for executables.  */
		  if ((abfd->flags & EXEC_P) == 0)
			{
			  obj_reloc_entry_size (abfd) = RELOC_STD_SIZE;
			  WRITE_HEADERS (abfd, execp);
			  return true;
			}

		  /* Otherwise (executables), do NOT use WRITE_HEADERS on plan9-i386:
			 it would write OMAGIC (0x107) instead of Plan 9 exec magic (0x1eb).  */
		  if (bfd_get_arch (abfd) != bfd_arch_i386)
			{
			  obj_reloc_entry_size (abfd) = RELOC_STD_SIZE;
			  WRITE_HEADERS (abfd, execp);
			  return true;
			}
		}

		  /* Plan 9 i386 executables: header magic 0x1eb, big-endian fields.
		   a_text = code_size + EXEC_BYTES_SIZE (Plan 9 native convention).
		   The kernel maps text at TEXTADDR (0x1000); the header occupies
		   [TEXTADDR, TEXTADDR+EXEC_BYTES_SIZE) and code follows, so
		   data_VMA = TEXTADDR + a_text = TEXTADDR + code_size + EXEC_BYTES_SIZE.
		   In the file, data starts at offset a_text (= code_size + header).
		   The symbol table is at file offset a_text + a_data.  */

		if (bfd_get_arch (abfd) == bfd_arch_i386)
		  {
			/* Plan 9 exec magic for i386.  */
			execp->a_info = 0x1eb;

			if (obj_textsec (abfd) != NULL)
			  execp->a_text = obj_textsec (abfd)->size + EXEC_BYTES_SIZE;

			execp->a_data = (obj_datasec (abfd) != NULL) ? obj_datasec (abfd)->size : 0;
			execp->a_bss  = (obj_bsssec (abfd)  != NULL) ? obj_bsssec  (abfd)->size : 0;
		  }
		else
		  {
			execp->a_info = 0; /* fallback */
		  }

	if (obj_aout_external_sym_count (abfd) != 0)
	  execp->a_syms = (obj_aout_external_sym_count (abfd)
			   * sizeof (struct external_nlist));

	execp->a_trsize = 0;
	execp->a_drsize = 0;

		execp->a_entry = bfd_get_start_address (abfd);

		plan9_swap_exec_header_out (abfd, execp, &exec_bytes);

		if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0)
		  return false;
		if (bfd_bwrite ((PTR) &exec_bytes, EXEC_BYTES_SIZE, abfd) != EXEC_BYTES_SIZE)
		  return false;

		return true;
}



/* Plan 9 exec headers are always big-endian (including sizes), even on i386.  */
static void
plan9_swap_exec_header_in (const struct external_exec *ext,
                           struct internal_exec *execp)
{
  execp->a_info   = bfd_getb32 (ext->e_info);
  execp->a_text   = bfd_getb32 (ext->e_text);
  execp->a_data   = bfd_getb32 (ext->e_data);
  execp->a_bss    = bfd_getb32 (ext->e_bss);
  execp->a_syms   = bfd_getb32 (ext->e_syms);
  execp->a_entry  = bfd_getb32 (ext->e_entry);
  execp->a_trsize = bfd_getb32 (ext->e_trsize);
  execp->a_drsize = bfd_getb32 (ext->e_drsize);
}

static void
plan9_swap_exec_header_out (bfd *abfd,
                            const struct internal_exec *execp,
                            struct external_exec *ext)
{
  bfd_putb32 (execp->a_info,  ext->e_info);
  bfd_putb32 (execp->a_text,  ext->e_text);
  bfd_putb32 (execp->a_data,  ext->e_data);
  bfd_putb32 (execp->a_bss,   ext->e_bss);
  bfd_putb32 (execp->a_syms,  ext->e_syms);
  bfd_putb32 (execp->a_entry, ext->e_entry);
  bfd_putb32 (execp->a_trsize,ext->e_trsize);
  bfd_putb32 (execp->a_drsize,ext->e_drsize);
}


/* Finish up the reading of an a.out file header */
static const bfd_target *
some_plan9_object_p (bfd *abfd,
                     struct internal_exec *execp,
                     const bfd_target *(*callback_to_real_object_p) (bfd *))
/*
     bfd *abfd;
     struct internal_exec *execp;
     const bfd_target *(*callback_to_real_object_p) PARAMS ((bfd *));
*/
{
/*
// moved some below, under result = callback_to_real_object_p(abfd)
	obj_sym_filepos(abfd) = N_SYMOFF(*execp);
	obj_str_filepos(abfd) = N_STROFF(*execp);
*/
	struct aout_data_struct *rawptr, *oldrawptr;
	const bfd_target *result;

	rawptr = (struct aout_data_struct  *) bfd_zalloc (abfd, sizeof (struct aout_data_struct ));
	if (rawptr == NULL)
		return 0;

	oldrawptr = abfd->tdata.aout_data;
	abfd->tdata.aout_data = rawptr;

	/* Copy the contents of the old tdata struct.*/
	if (oldrawptr != NULL)
		*abfd->tdata.aout_data = *oldrawptr;

	abfd->tdata.aout_data->a.hdr = &rawptr->e;
	*(abfd->tdata.aout_data->a.hdr) = *execp;	/* Copy in the internal_exec struct */
	execp = abfd->tdata.aout_data->a.hdr;

	/* Set the file flags */
	abfd->flags = BFD_NO_FLAGS;
	/* Setting of EXEC_P has been deferred to the bottom of this function */
	if (execp->a_syms)
		abfd->flags |= HAS_LINENO | HAS_DEBUG | HAS_SYMS | HAS_LOCALS;
	if (N_DYNAMIC(*execp))
		abfd->flags |= DYNAMIC;

	adata (abfd).magic = z_magic;

	/* stupid hack, because N_HEADER_IN_TEXT can't describe us exactly */
	//execp->a_text += 0x20;

	bfd_get_start_address (abfd) = execp->a_entry;

/* 
// Olde code - caused segfault on linker
	obj_aout_symbols (abfd) = (aout_symbol_type *)NULL;
	bfd_get_symcount (abfd) = 0;	/ * XXX * /
	obj_reloc_entry_size (abfd) = 1;
	obj_symbol_entry_size (abfd) = 1;
*/
	bfd_get_symcount (abfd) = execp->a_syms / sizeof (struct external_nlist);
	obj_reloc_entry_size (abfd) = RELOC_STD_SIZE;
	obj_symbol_entry_size (abfd) = EXTERNAL_NLIST_SIZE;

#ifdef USE_MMAP
	bfd_init_window (&obj_aout_sym_window (abfd));
	bfd_init_window (&obj_aout_string_window (abfd));
#endif
	obj_aout_external_syms (abfd) = NULL;
	obj_aout_external_strings (abfd) = NULL;
	obj_aout_sym_hashes (abfd) = NULL;

	if (! NAME(aout,make_sections) (abfd))
		return NULL;

	obj_textsec (abfd)->filepos = EXEC_BYTES_SIZE;
	/* a_text = code_size + EXEC_BYTES_SIZE (Plan 9 convention).
	   Data follows text in the file at offset a_text.
	   The previous (buggy) formula used EXEC_BYTES_SIZE + execp->a_text,
	   which double-counts the header (EXEC_BYTES_SIZE + code_size +
	   EXEC_BYTES_SIZE) and is inconsistent with native Plan 9 binaries
	   where data is at file offset a_text, not EXEC_BYTES_SIZE + a_text.  */
	obj_datasec (abfd)->filepos = execp->a_text;
	obj_sym_filepos (abfd) = obj_datasec (abfd)->filepos + execp->a_data;

	obj_datasec (abfd)->rawsize = execp->a_data;
	obj_bsssec (abfd)->rawsize = execp->a_bss;

	/* Keep canonical section sizes in sync with rawsize.
     objdump/size use section->size, not rawsize.  */
	obj_textsec (abfd)->size = obj_textsec (abfd)->rawsize;
	obj_datasec (abfd)->size = obj_datasec (abfd)->rawsize;
	obj_bsssec  (abfd)->size = obj_bsssec  (abfd)->rawsize;

	obj_textsec (abfd)->flags =
		(execp->a_trsize != 0
		? (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS | SEC_RELOC)
		: (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS));
	obj_datasec (abfd)->flags =
		(execp->a_drsize != 0
		? (SEC_ALLOC | SEC_LOAD | SEC_DATA | SEC_HAS_CONTENTS | SEC_RELOC)
		: (SEC_ALLOC | SEC_LOAD | SEC_DATA | SEC_HAS_CONTENTS));
	obj_bsssec (abfd)->flags = SEC_ALLOC;

	result = (*callback_to_real_object_p) (abfd);
	if (result == NULL)
	  return NULL;

  /* The generic a.out callback uses N_TXTADDR/N_DATADDR which are
     wrong for Plan 9 (they return 0 and 0x1000 respectively, based on
     the generic OMAGIC/ZMAGIC rules and the 0x1eb magic).
     Override with the correct Plan 9 i386 VMAs:
       text: TEXTADDR + EXEC_BYTES_SIZE = 0x1000 + 32 = 0x1020
             (header occupies 0x1000..0x101f, code starts at 0x1020)
       data: TEXTADDR + a_text = 0x1000 + a_text
             (Plan 9 a_text = code_size + EXEC_BYTES_SIZE, so data
             starts at 0x1000 + code_size + 32 = 0x1020 + code_size)
       bss:  data_vma + a_data  */
  obj_textsec (abfd)->vma = (bfd_vma) TEXT_START_ADDR + EXEC_BYTES_SIZE;
  obj_datasec (abfd)->vma = (bfd_vma) TEXT_START_ADDR + execp->a_text;
  obj_bsssec  (abfd)->vma = (bfd_vma) TEXT_START_ADDR + execp->a_text
                             + execp->a_data;
  obj_textsec (abfd)->lma = obj_textsec (abfd)->vma;
  obj_datasec (abfd)->lma = obj_datasec (abfd)->vma;
  obj_bsssec  (abfd)->lma = obj_bsssec  (abfd)->vma;

  /* The generic a.out callback recalculates section file positions and
	   obj_sym_filepos using N_SYMOFF, which does not always match the
	   Plan 9 0x1eb layout.  Re-assert the correct positions explicitly:
	   text immediately after the fixed-size header (at EXEC_BYTES_SIZE),
	   data at file offset a_text (since Plan 9 a_text = code_size +
	   EXEC_BYTES_SIZE, the header is included in the text file span),
	   and symbols contiguously after data.  */
  obj_textsec (abfd)->filepos = EXEC_BYTES_SIZE;
  obj_datasec (abfd)->filepos = execp->a_text;
  obj_sym_filepos (abfd) = obj_datasec (abfd)->filepos + execp->a_data;
  obj_str_filepos (abfd) = obj_sym_filepos (abfd) + execp->a_syms;

  /* Now that the segment addresses have been worked out, take a better
     guess at whether the file is executable.  If the entry point
     is within the text segment, assume it is.  (This makes files
     executable even if their entry point address is 0, as long as
     their text starts at zero.).

     This test had to be changed to deal with systems where the text segment
     runs at a different location than the default.  The problem is that the
     entry address can appear to be outside the text segment, thus causing an
     erroneous conclusion that the file isn't executable.

     To fix this, we now accept any non-zero entry point as an indication of
     executability.  This will work most of the time, since only the linker
     sets the entry point, and that is likely to be non-zero for most systems.  */

	if (execp->a_entry != 0
		|| (execp->a_entry >= obj_textsec(abfd)->vma
			&& execp->a_entry < obj_textsec(abfd)->vma + obj_textsec(abfd)->rawsize))
	abfd->flags |= EXEC_P;
#ifdef STAT_FOR_EXEC
	else {
		struct stat stat_buf;

		/* The original heuristic doesn't work in some important cases.
			The a.out file has no information about the text start
			address.  For files (like kernels) linked to non-standard
			addresses (ld -Ttext nnn) the entry point may not be between
			the default text start (obj_textsec(abfd)->vma) and
			(obj_textsec(abfd)->vma) + text size.  This is not just a mach
			issue.  Many kernels are loaded at non standard addresses.  */
		if (abfd->iostream != NULL
		&& (abfd->flags & BFD_IN_MEMORY) == 0
		&& (fstat(fileno((FILE *) (abfd->iostream)), &stat_buf) == 0)
		&& ((stat_buf.st_mode & 0111) != 0))
			abfd->flags |= EXEC_P;
	}
#endif /* STAT_FOR_EXEC */

	if (result) {
#if 0 /* These should be set correctly anyways.  */
		abfd->sections = obj_textsec (abfd);
		obj_textsec (abfd)->next = obj_datasec (abfd);
		obj_datasec (abfd)->next = obj_bsssec (abfd);
#endif
	}
	else {
		free (rawptr);
		abfd->tdata.aout_data = oldrawptr;
	}
	return result;
}

/*
static const bfd_target *MY(object_p) PARAMS ((bfd *));
*/
static const bfd_target *MY (object_p) (bfd *abfd);



static const bfd_target *
MY (object_p) (bfd *abfd)
{
  struct external_exec exec_bytes;    /* Raw exec header from file */
  struct internal_exec exec;          /* Decoded exec header */
  const bfd_target *target;
  bfd_vma be_info;

  /* Read raw exec header.  */
  if (bfd_bread ((PTR) &exec_bytes, EXEC_BYTES_SIZE, abfd) != EXEC_BYTES_SIZE)
    {
      if (bfd_get_error () != bfd_error_system_call)
        bfd_set_error (bfd_error_wrong_format);
      return 0;
    }

  memset (&exec, 0, sizeof (exec));

  /* Plan 9 exec headers are always big-endian (including sizes), even on i386.  */
  be_info = bfd_getb32 (exec_bytes.e_info);

  if (be_info == 0x000001eb)
    {
      /* Decode full header as BE.  */
      plan9_swap_exec_header_in (&exec_bytes, &exec);

      /* Validate magic after decoding.  */
      if (N_BADMAG (exec))
        return 0;

      target = some_plan9_object_p (abfd, &exec, MY (callback));
      return target;
    }

  /* Non-Plan9: decode using generic a.out rules.  */
  NAME (aout, swap_exec_header_in) (abfd, &exec_bytes, &exec);

  if (N_BADMAG (exec))
    return 0;

  target = NAME (aout, some_aout_object_p) (abfd, &exec, MY (callback));
  if (target != NULL && N_MAGIC (exec) == OMAGIC)
    abfd->flags &= ~EXEC_P;
  return target;
}


/* Skip the 2-byte big-endian pair suffix in Plan 9 'z'/'Z' (AHISTORY)
   symbol-table records.  After the NUL-terminated file name, the linker
   appends pairs of big-endian 2-byte values terminated by 0x0000.  Return
   the updated pointer (pointing one past the terminator pair, or ep if the
   terminator was not found before end-of-data).  */
static unsigned char *
plan9_skip_zrec_suffix (unsigned char *p, unsigned char *ep)
{
  while (p + 2 <= ep)
    {
      unsigned int pair = bfd_getb16 ((PTR) p);
      p += 2;
      if (pair == 0)
        break;
    }
  return p;
}

/* Return non-zero if the first record in DATA..EP looks like a Plan 9
   inline symbol record rather than an a.out external_nlist entry.
   Plan 9 inline records begin with:
     4-byte value | 1-byte type | NUL-terminated inline name
   The type byte is alphabetic ('T', 't', 'D', 'd', 'B', 'b', 'f', 'm',
   'p', 'a', 'z', ...), and non-z/Z records have a non-empty inline name.
   external_nlist entries do not match that layout: byte 4 is n_type
   (small numeric flags), not an alphabetic symbol code.  */
static boolean
plan9_inline_symbol_p (unsigned char *data, unsigned char *ep)
{
  unsigned char stype;
  unsigned char *name;

  if (ep - data < 6)
    return false;

  stype = data[4] & ~0x80;
  if (! ((stype >= 'A' && stype <= 'Z')
	 || (stype >= 'a' && stype <= 'z')))
    return false;

  name = data + 5;
  while (name < ep && *name != '\0')
    name++;

  if (name >= ep)
    return false;

  return (stype == 'z' || stype == 'Z' || name > data + 5);
}

static boolean
MY(slurp_symbol_table) (bfd *abfd)
/*
     bfd *abfd;
*/
{
	aout_symbol_type *cached;
	size_t cached_size;
	unsigned char *syms, *p, *ep, *name;
	int i, n, nsyms;
	asection *sec;

	/* been here, done that */
	if (obj_aout_symbols (abfd) != NULL)
		return true;

	n = exec_hdr (abfd)->a_syms;
	if (n == 0)
		return true;

	/* Read the raw symbol bytes first.  Most Plan 9 files use the native
	   inline symbol stream:
	     4-byte big-endian value | 1-byte type | NUL-terminated inline name
	   Some checked-in OMAGIC fixtures (e.g. reloc_test.o) use ordinary
	   a.out external_nlist + string-table layout instead.  Prefer the
	   inline format when the bytes actually look like inline records, and
	   only fall back to external_nlist when they do not.  */
	syms = (unsigned char *) bfd_malloc (n);
	if (syms == NULL)
		return false;

	if (bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0
	    || bfd_bread ((PTR) syms, n, abfd) != n)
	{
		free (syms);
		return false;
	}

	if (! plan9_inline_symbol_p (syms, syms + n)
	    && (bfd_size_type) n >= sizeof (struct external_nlist)
	    && (bfd_size_type) n % sizeof (struct external_nlist) == 0)
	{
		struct external_nlist *esyms;

		esyms = (struct external_nlist *) syms;

		{
			/* external_nlist + string-table format.
			   Read the string table and use the public
			   NAME(aout, translate_symbol_table) to convert it.  */
			bfd_size_type symcount = n / sizeof (struct external_nlist);
			unsigned char *strtab;
			bfd_size_type strsize;

			/* Read string table: 4-byte size header + string data.
			   Allocate size+1 bytes; zero [0..3] so that n_strx==0 yields
			   an empty string; read string payload into [4..strsize-1].  */
			{
				unsigned char sbuf[4];

				if (bfd_seek (abfd, obj_str_filepos (abfd), SEEK_SET) != 0
				    || bfd_bread ((PTR) sbuf, (bfd_size_type) 4, abfd) != 4)
				{
					free (syms);
					return false;
				}
				strsize = bfd_h_get_32 (abfd, (PTR) sbuf);
			}

			if (strsize < 4)
			{
				free (syms);
				return false;
			}

			strtab = (unsigned char *) bfd_malloc (strsize + 1);
			if (strtab == NULL)
			{
				free (syms);
				return false;
			}
			memset (strtab, 0, 4);  /* n_strx==0 -> empty string */

			if (bfd_seek (abfd, obj_str_filepos (abfd) + 4, SEEK_SET) != 0
			    || bfd_bread ((PTR) (strtab + 4),
					  strsize - 4, abfd) != strsize - 4)
			{
				free (strtab);
				free (syms);
				return false;
			}
			strtab[strsize] = '\0';

			cached_size = symcount * sizeof (aout_symbol_type);
			cached = (aout_symbol_type *) bfd_malloc (cached_size);
			if (cached == NULL)
			{
				free (strtab);
				free (syms);
				return false;
			}
			memset (cached, 0, cached_size);

			if (! NAME (aout, translate_symbol_table)
			      (abfd, cached, esyms, symcount,
			       (char *) strtab, strsize, FALSE))
			{
				free (cached);
				free (strtab);
				free (syms);
				return false;
			}

			bfd_get_symcount (abfd) = symcount;
			obj_aout_external_sym_count (abfd) = symcount;
			obj_aout_symbols (abfd) = cached;
			obj_aout_external_syms (abfd) = esyms;
			obj_aout_external_strings (abfd) = (char *) strtab;
			obj_aout_external_string_size (abfd) = strsize;
			return true;
		}
	}

	/* Plan 9 inline format: use the bytes we already read from
	   obj_sym_filepos(abfd).  For Plan 9 0x1eb executables, obj_sym_filepos
	   is restored after the generic a.out callback to
	   EXEC_BYTES_SIZE + a_text + a_data.
	   Each record: 4-byte big-endian value | 1-byte type | NUL-terminated
	   name.
	   Exception: 'z'/'Z' (AHISTORY) records carry an extra suffix of
	   big-endian 2-byte pairs terminated by 0x0000 after the name.  */
	p = syms;
	ep = syms + n;
	nsyms = 0;

	/* Counting pass: scan the variable-length stream to count non-z/Z records. */
	while (p < ep)
	{
		unsigned char stype;

		if (ep - p < 5)
			break;

		stype = p[4] & ~0x80;
		p += 5;

		while (p < ep && *p != '\0')
			p++;

		if (p >= ep)
			break;

		p++;  /* skip NUL terminator */

		if (stype == 'z' || stype == 'Z')
		{
			p = plan9_skip_zrec_suffix (p, ep);
			continue;  /* z/Z records are not nm symbols */
		}

		nsyms++;
	}

	bfd_get_symcount (abfd) = nsyms;
	obj_aout_external_sym_count (abfd) = nsyms;

	if (nsyms == 0)
	{
		obj_aout_symbols (abfd) = NULL;
		free (syms);
		return true;
	}

	cached_size = nsyms * sizeof (aout_symbol_type);
	cached = (aout_symbol_type *) bfd_malloc (cached_size);
	if (cached == NULL)
	{
		free (syms);
		return false;
	}
	memset (cached, 0, cached_size);

	/* Parsing pass: fill in cached[] for each non-z/Z record. */
	p = syms;
	i = 0;
	while (p < ep && i < nsyms)
	{
		unsigned char stype;

		if (ep - p < 5)
			break;

		cached[i].symbol.the_bfd = abfd;
		cached[i].symbol.value = bfd_h_get_32 (abfd, p);
		cached[i].symbol.name = NULL;
		cached[i].symbol.flags = 0;
		cached[i].symbol.section = bfd_und_section_ptr;

		stype = (unsigned char) (p[4] & ~0x80);
		p += 5;

		name = p;
		while (name < ep && *name != '\0')
			name++;

		if (name >= ep)
			break;

		if (stype == 'z' || stype == 'Z')
		{
			p = name + 1;
			p = plan9_skip_zrec_suffix (p, ep);
			continue;
		}

		cached[i].symbol.name = strdup ((char *) p);
		if (cached[i].symbol.name == NULL)
		{
			free (cached);
			free (syms);
			return false;
		}

		sec = bfd_und_section_ptr;

		switch (stype)
		{
		case 'T':
		case 'L':
			cached[i].symbol.flags = BSF_GLOBAL;
			sec = obj_textsec (abfd);
			break;

		case 't':
		case 'l':
			cached[i].symbol.flags = BSF_LOCAL;
			sec = obj_textsec (abfd);
			break;

		case 'D':
			cached[i].symbol.flags = BSF_GLOBAL;
			sec = obj_datasec (abfd);
			break;

		case 'd':
			cached[i].symbol.flags = BSF_LOCAL;
			sec = obj_datasec (abfd);
			break;

		case 'B':
			cached[i].symbol.flags = BSF_GLOBAL;
			sec = obj_bsssec (abfd);
			break;

		case 'b':
			cached[i].symbol.flags = BSF_LOCAL;
			sec = obj_bsssec (abfd);
			break;

		default:
			sec = bfd_und_section_ptr;
			cached[i].symbol.flags = 0;
			break;
		}

		cached[i].symbol.section = sec;

		if (sec == obj_textsec (abfd)
		    || sec == obj_datasec (abfd)
		    || sec == obj_bsssec (abfd))
			cached[i].symbol.value -= sec->vma;

		p = name + 1;
		i++;
	}

	bfd_get_symcount (abfd) = i;
	obj_aout_external_sym_count (abfd) = i;

	obj_aout_symbols (abfd) = cached;
	free (syms);
	return true;
}


long
plan9_i386_canonicalize_symtab (bfd *abfd, asymbol **location);

long
MY(get_symtab) (bfd *abfd, asymbol **location)
/*
     bfd *abfd;
     asymbol **location;
*/
{
	int i;
	aout_symbol_type *s;

	if (!MY(slurp_symbol_table)(abfd))
		return -1;

	s = obj_aout_symbols(abfd);
	for (i = 0; i < (int) bfd_get_symcount (abfd); i++)
		*(location++) = (asymbol *)(s++);
	*location++ =0;
	return bfd_get_symcount (abfd);
}

long
plan9_i386_get_symtab_upper_bound (bfd *abfd)
/*
     bfd *abfd;
*/
{
	if (!MY(slurp_symbol_table)(abfd))
		return -1;

	return (bfd_get_symcount (abfd)+1) * (sizeof (aout_symbol_type *));
}


long
plan9_i386_canonicalize_symtab (bfd *abfd, asymbol **location)
{
	int i;
	aout_symbol_type *s;

	if (!MY(slurp_symbol_table) (abfd))
		return -1;

	s = obj_aout_symbols (abfd);
	for (i = 0; i < (int) bfd_get_symcount (abfd); i++)
		*(location++) = (asymbol *) (s++);
	*location++ = 0;

	return bfd_get_symcount (abfd);
}


long
plan9_i386_read_minisymbols (bfd *abfd, bfd_boolean dynamic,
			     void **minisymsp, unsigned int *sizep)
{
	long storage;
	asymbol **syms;
	long count;

	if (dynamic)
		return -1;

	storage = plan9_i386_get_symtab_upper_bound (abfd);
	if (storage <= 0)
		return storage;

	syms = (asymbol **) bfd_malloc (storage);
	if (syms == NULL)
		return -1;

	count = plan9_i386_canonicalize_symtab (abfd, syms);
	if (count < 0)
	{
		free (syms);
		return -1;
	}

	*minisymsp = syms;
	*sizep = sizeof (asymbol *);

	return count;
}


asymbol *
plan9_i386_minisymbol_to_symbol (bfd *abfd, bfd_boolean dynamic,
				 const void *minisym, asymbol *store)
{
	asymbol *sym;

	// Very noisy - disabled.
	//fprintf (stderr, "DBG P9 MINISYM_TO_SYMBOL dynamic=%d\n", dynamic);

	if (dynamic)
		return NULL;

	sym = *(asymbol * const *) minisym;
	if (sym == NULL)
		return NULL;

	*store = *sym;
	return store;
}

/* On Plan 9, the magic number is always in big-endian format.  */

const bfd_target MY(vec) =
{
  TARGETNAME,		/* name */
  bfd_target_aout_flavour,
#ifdef TARGET_IS_BIG_ENDIAN_P
  BFD_ENDIAN_BIG,		/* target byte order (big) */
#else
  BFD_ENDIAN_LITTLE,		/* target byte order (little) */
#endif
  BFD_ENDIAN_BIG,		/* target headers byte order (big) */
  (HAS_RELOC | EXEC_P |		/* object flags */
   HAS_LINENO | HAS_DEBUG |
   HAS_SYMS | HAS_LOCALS | DYNAMIC | WP_TEXT | D_PAGED),
  (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_LOAD | SEC_RELOC | SEC_CODE | SEC_DATA),
  MY_symbol_leading_char,
  AR_PAD_CHAR,			/* ar_pad_char */
  15,				/* ar_max_namelen */
#ifdef TARGET_IS_BIG_ENDIAN_P
  bfd_getb64, bfd_getb_signed_64, bfd_putb64,
     bfd_getb32, bfd_getb_signed_32, bfd_putb32,
     bfd_getb16, bfd_getb_signed_16, bfd_putb16, /* data */
#else
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
     bfd_getl32, bfd_getl_signed_32, bfd_putl32,
     bfd_getl16, bfd_getl_signed_16, bfd_putl16, /* data */
#endif
  bfd_getb64, bfd_getb_signed_64, bfd_putb64,
     bfd_getb32, bfd_getb_signed_32, bfd_putb32,
     bfd_getb16, bfd_getb_signed_16, bfd_putb16, /* hdrs */
    {_bfd_dummy_target, MY_object_p, /* bfd_check_format */
       bfd_generic_archive_p, MY_core_file_p},
    {bfd_false, MY_mkobject,	/* bfd_set_format */
       _bfd_generic_mkarchive, bfd_false},
    {bfd_false, MY_write_object_contents, /* bfd_write_contents */
       _bfd_write_archive_contents, bfd_false},

     BFD_JUMP_TABLE_GENERIC (MY),
     BFD_JUMP_TABLE_COPY (MY),			/* _bfd_generic */
     BFD_JUMP_TABLE_CORE (MY),			/* _bfd_nocore */
     BFD_JUMP_TABLE_ARCHIVE (MY),		/* _bfd_noarchive */
     BFD_JUMP_TABLE_SYMBOLS (MY),
     BFD_JUMP_TABLE_RELOCS (MY),			/* _bfd_norelocs */
     BFD_JUMP_TABLE_WRITE (MY),
     BFD_JUMP_TABLE_LINK (MY),
     BFD_JUMP_TABLE_DYNAMIC (MY),		/* _bfd_nodynamic */

  /* Alternative_target */
  NULL,

  (PTR) MY_backend_data
};
