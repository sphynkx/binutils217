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
/*
#define DEBUG_PLAN9
*/

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
#define MY_object_p MY(object_p)
#define MY_write_object_contents MY(write_object_contents)
//#define MY_get_symtab_upper_bound plan9_i386_get_symtab_upper_bound
//#define MY_get_symtab plan9_i386_get_symtab

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


#define	N_BADMAG(x) (N_MAGIC(x) != QMAGIC && N_MAGIC(x) != OMAGIC)
#define	MY_backend_data &MY(backend_data)

#undef N_SYMOFF
#define N_SYMOFF(x)	( N_MAGIC(x) == QMAGIC ? N_DATOFF(x) + (x).a_data : N_DRELOFF(x) + (x).a_drsize )

#include "aout-target.h"

static CONST struct aout_backend_data MY(backend_data) = {
	0,	/* zmagic_contiguous */
	1,	/* text_includes_header */
	0,	/* entry_is_text_address */
	0,	/* exec_hdr_flags */
	0x1020,	/* default_text_vma */
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


/* DBG block start */
#ifdef DEBUG_PLAN9
  {
    asection *s;
    fprintf (stderr, "DBG BFD WRITE1: start=%#lx output_has_begun=%d\n",
             (unsigned long) bfd_get_start_address (abfd),
             (int) abfd->output_has_begun);
    for (s = abfd->sections; s != NULL; s = s->next)
      {
        fprintf (stderr,
                 "DBG BFD WRITE2: sec=%s vma=%#lx size=%#lx rawsize=%#lx filepos=%#lx flags=%#lx\n",
                 s->name ? s->name : "(null)",
                 (unsigned long) s->vma,
                 (unsigned long) s->size,
                 (unsigned long) s->rawsize,
                 (unsigned long) s->filepos,
                 (unsigned long) s->flags);
      }
  }
#endif
/* DBG block end */


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

      text_vma = 0x1020;
      data_vma = 0x2000;

      /* Place bss after data; keep 0x1000 alignment like the rest of the format. */
      bss_vma = data_vma + obj_datasec (abfd)->size;
      bss_vma = (bss_vma + 0xfff) & ~((bfd_vma) 0xfff);

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
		   IMPORTANT: a_text must describe the *gap* from text base (0x1020)
		   to data base (0x2000), not a page-rounded text size, otherwise the
		   loader will place data/bss at the wrong address.  */

		if (bfd_get_arch (abfd) == bfd_arch_i386)
		  {
			/* Plan 9 exec magic for i386.  */
			execp->a_info = 0x1eb;

			/* Make header sizes consistent with fixed VMAs.  */
			if (obj_textsec (abfd) != NULL && obj_datasec (abfd) != NULL)
			  {
				bfd_vma text_vma = obj_textsec (abfd)->vma;
				bfd_vma data_vma = obj_datasec (abfd)->vma;

				if (text_vma != 0 && data_vma > text_vma)
				  execp->a_text = (bfd_vma) (data_vma - text_vma);
				else
				  execp->a_text = obj_textsec (abfd)->size;
			  }
			else if (obj_textsec (abfd) != NULL)
			  execp->a_text = obj_textsec (abfd)->size;

			execp->a_data = (obj_datasec (abfd) != NULL) ? obj_datasec (abfd)->size : 0;
			execp->a_bss  = (obj_bsssec (abfd)  != NULL) ? obj_bsssec  (abfd)->size : 0;
		  }
		else
		  {
			execp->a_info = 0; /* fallback */
		  }

		execp->a_syms = obj_sym_filepos (abfd) - N_SYMOFF (*execp);
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

	obj_sym_filepos(abfd) = N_SYMOFF(*execp);
	obj_str_filepos(abfd) = N_STROFF(*execp);

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
  return target;
}


static boolean
putsym(bfd *abfd, int type, char *prefix, char *name, bfd_vma value)
/*
	bfd *abfd;
	int type;
	char *prefix;
	char *name;
	bfd_vma value;
*/
{
	int n;
	char buf[5];

	if(bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0)
		return false;

	bfd_h_put_32(abfd, value, buf);
	buf[4] = type | 0x80;
	if((int)bfd_write ((PTR) buf, (bfd_size_type) sizeof(buf), (bfd_size_type) 1, abfd) != sizeof(buf))
		return false;
	obj_sym_filepos (abfd) += sizeof(buf);

	if(prefix != 0) {
		n = strlen(prefix);
		if((int)bfd_write ((PTR) prefix, (bfd_size_type) n, (bfd_size_type) 1, abfd) != n)
			return false;
		obj_sym_filepos (abfd) += n;
	}

	n = strlen(name)+1;
	if((int)bfd_write ((PTR) name, (bfd_size_type) n, (bfd_size_type) 1, abfd) != n)
		return false;
	obj_sym_filepos (abfd) += n;

	++obj_aout_external_sym_count (abfd);
	return true;
}


static boolean
MY(slurp_symbol_table) (bfd *abfd)
{
  aout_symbol_type *cached;
  bfd_size_type cached_size;
  struct external_nlist *syms;
  bfd_size_type sym_bytes;
  bfd_size_type sym_count;
  char *strings;
  bfd_size_type str_size;
  bfd_byte lenbuf[4];
  bfd_size_type i;
  struct internal_exec *execp;
  file_ptr sympos;
  file_ptr strpos;

  /* been here, done that */
  if (obj_aout_symbols (abfd) != NULL)
    return true;

  execp = exec_hdr (abfd);
  sym_bytes = execp->a_syms;
  if (sym_bytes == 0)
    return true;

  /* Sanity: must be multiple of external nlist size.  */
  if ((sym_bytes % EXTERNAL_NLIST_SIZE) != 0)
    {
      bfd_set_error (bfd_error_wrong_format);
      return false;
    }

  sym_count = sym_bytes / EXTERNAL_NLIST_SIZE;

  sympos = obj_sym_filepos (abfd);
  if (sympos == 0)
    {
      /* If backend didn't set it, fall back to a.out macro.  */
      sympos = (file_ptr) N_SYMOFF (*execp);
      obj_sym_filepos (abfd) = sympos;
    }

  /* String table position: usually immediately after symtab.  */
  strpos = obj_str_filepos (abfd);
  if (strpos == 0)
    {
      strpos = (file_ptr) N_STROFF (*execp);
      obj_str_filepos (abfd) = strpos;
    }

  /* Read external nlist array.  Keep it in tdata so linker can use it.  */
  syms = (struct external_nlist *) bfd_malloc (sym_bytes);
  if (syms == NULL)
    return false;

  if (bfd_seek (abfd, sympos, SEEK_SET) != 0
      || bfd_bread ((void *) syms, sym_bytes, abfd) != sym_bytes)
    {
      free (syms);
      return false;
    }

  /* Read string table length (big-endian 32-bit), then strings.  */
  if (bfd_seek (abfd, strpos, SEEK_SET) != 0
      || bfd_bread ((void *) lenbuf, (bfd_size_type) 4, abfd) != 4)
    {
      free (syms);
      return false;
    }

  str_size = bfd_getb32 (lenbuf);

  /* In a.out the length includes the 4-byte length itself.
     Accept 0/4 as empty.  */
  if (str_size < 4)
    {
      /* Treat as empty strings.  */
      str_size = 0;
      strings = NULL;
    }
  else
    {
      bfd_size_type payload = str_size - 4;

      strings = (char *) bfd_malloc (payload);
      if (strings == NULL)
        {
          free (syms);
          return false;
        }

      if (payload != 0
          && bfd_bread ((void *) strings, payload, abfd) != payload)
        {
          free (strings);
          free (syms);
          return false;
        }

      /* For convenience, keep external_string_size as payload bytes.  */
      str_size = payload;
    }

  /* Build cached canonical symbols.  */
  cached_size = sym_count * sizeof (aout_symbol_type);
  cached = (aout_symbol_type *) bfd_malloc (cached_size);
  if (cached == NULL && cached_size != 0)
    {
      if (strings) free (strings);
      free (syms);
      return false;
    }
  if (cached_size != 0)
    memset (cached, 0, cached_size);

  for (i = 0; i < sym_count; i++)
    {
      unsigned long n_strx;
      unsigned int type;
      bfd_vma value;
      asection *sec;

      n_strx = bfd_getb32 (syms[i].e_strx);
      type = syms[i].e_type[0];
      value = bfd_getb32 (syms[i].e_value);

      cached[i].symbol.the_bfd = abfd;
      cached[i].symbol.value = value;

      /* Name resolution.  */
      if (strings == NULL || n_strx == 0)
        {
          cached[i].symbol.name = "";
        }
      else if (n_strx >= str_size)
        {
          /* Bad string index => wrong format.  */
          cached[i].symbol.name = "";
          /* You can also choose to fail hard here:
             bfd_set_error (bfd_error_wrong_format); ... */
        }
      else
        {
          cached[i].symbol.name = strings + n_strx;
        }

      /* Section + flags.  Only handle the standard N_TYPE cases.  */
      sec = bfd_abs_section_ptr;

      switch (type & N_TYPE)
        {
        case N_TEXT:
          sec = obj_textsec (abfd);
          break;
        case N_DATA:
          sec = obj_datasec (abfd);
          break;
        case N_BSS:
          sec = obj_bsssec (abfd);
          break;
        case N_UNDF:
          sec = bfd_und_section_ptr;
          break;
        default:
          /* Stabs/debug/etc: mark as debugging to keep BFD/linker sane.  */
          cached[i].symbol.flags |= BSF_DEBUGGING;
          sec = bfd_abs_section_ptr;
          break;
        }

      cached[i].symbol.section = sec;

      if (type & N_EXT)
        cached[i].symbol.flags |= BSF_GLOBAL;
      else
        cached[i].symbol.flags |= BSF_LOCAL;
    }

  obj_aout_symbols (abfd) = cached;
  bfd_get_symcount (abfd) = sym_count;

  /* Make generic a.out code happy: store external tables too.  */
  obj_aout_external_syms (abfd) = syms;
  obj_aout_external_sym_count (abfd) = sym_count;
  obj_aout_external_strings (abfd) = strings;
  obj_aout_external_string_size (abfd) = str_size;

  return true;
}

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
MY(get_symtab_upper_bound) (bfd *abfd)
/*
     bfd *abfd;
*/
{
	if (!MY(slurp_symbol_table)(abfd))
		return -1;

	return (bfd_get_symcount (abfd)+1) * (sizeof (aout_symbol_type *));
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

