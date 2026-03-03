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

/* Plan 9 uses static linking.  Disable/ignore dynamic-link related hooks.  */

/* Plan 9 uses static linking; ignore dynamic-link related hooks.  */

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
	MY(add_one_symbol),
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

	if(adata(abfd).magic == o_magic) {
		obj_reloc_entry_size (abfd) = RELOC_STD_SIZE;
		WRITE_HEADERS(abfd, execp);
		return true;
	}

	switch (bfd_get_arch(abfd)) {
	case bfd_arch_i386:
		execp->a_info = QMAGIC;
		break;
	default:
		execp->a_info = 0;
		break;
	}

	execp->a_syms = obj_sym_filepos (abfd)-N_SYMOFF (*execp);
	execp->a_trsize = 0;
	execp->a_drsize = 0;
	execp->a_entry = bfd_get_start_address (abfd);

	/* stupid hack, because N_HEADER_IN_TEXT can't describe us exactly */
	execp->a_text -= 0x20;

	NAME(aout,swap_exec_header_out) (abfd, execp, &exec_bytes);

	if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0) return false;
	if (bfd_write ((PTR) &exec_bytes, 1, EXEC_BYTES_SIZE, abfd) != EXEC_BYTES_SIZE)
		return false;

	return true;
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
	execp->a_text += 0x20;

	bfd_get_start_address (abfd) = execp->a_entry;

	obj_aout_symbols (abfd) = (aout_symbol_type *)NULL;
	bfd_get_symcount (abfd) = 0;	/* XXX */
	obj_reloc_entry_size (abfd) = 1;
	obj_symbol_entry_size (abfd) = 1;

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
MY(object_p) (bfd *abfd)
/*
     bfd *abfd;
*/
{
	struct external_exec exec_bytes;	/* Raw exec header from file */
	struct internal_exec exec;		/* Cleaned-up exec header */
	const bfd_target *target;

	if (bfd_read ((PTR) &exec_bytes, 1, EXEC_BYTES_SIZE, abfd) != EXEC_BYTES_SIZE) {
		if (bfd_get_error () != bfd_error_system_call)
			bfd_set_error (bfd_error_wrong_format);
		return 0;
	}

	exec.a_info = bfd_h_get_32 (abfd, exec_bytes.e_info);

	if (N_BADMAG (exec))
		return 0;

	NAME(aout,swap_exec_header_in) (abfd, &exec_bytes, &exec);
	if(N_MAGIC(exec) == QMAGIC)
		target = some_plan9_object_p (abfd, &exec, MY(callback));
	else
		target = NAME(aout,some_aout_object_p)  (abfd, &exec, MY(callback));
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
/*
     bfd *abfd;
*/
{
	aout_symbol_type *cached;
	size_t cached_size;
	unsigned char *syms, *p, *ep;
	int i, n, nsyms;
	asection *sec;

	/* been here, done that */
	if (obj_aout_symbols (abfd) != NULL)
		return true;

	n = exec_hdr (abfd)->a_syms;
	if(n == 0)
		return true;
	syms = bfd_malloc(n);
	if (syms == NULL)
		return false;
	if (bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0
	|| ((int)bfd_read (syms, 1, n , abfd) != n )) {
		free (syms);
		return false;
	}
	p = syms;
	ep = p+n;
	nsyms = 0;
	for(;;) {
		p += 5;
		while(p < ep && *p != '\0')
			p++;
		nsyms++;
	}
	bfd_get_symcount (abfd) = nsyms;
	obj_aout_external_sym_count (abfd) = nsyms;

	cached_size = (nsyms * sizeof (aout_symbol_type));
	cached = (aout_symbol_type *) bfd_malloc (cached_size);
	if (cached == NULL && cached_size != 0)
		return false;
	if (cached_size != 0)
		memset (cached, 0, cached_size);

 	p = syms;
	for(i = 0; i < nsyms; i++) {
		cached[i].symbol.value = bfd_h_get_32(abfd, p);
		cached[i].symbol.name = strdup(&p[5]);
		switch(p[4] & ~0x80) {
		case 'T':
		case 'L':
			cached[i].symbol.flags = BSF_GLOBAL;
			sec = obj_textsec(abfd);
		case 't':
		case 'l':
			cached[i].symbol.flags = BSF_LOCAL;
			sec = obj_textsec(abfd);
		case 'D':
			cached[i].symbol.flags = BSF_GLOBAL;
			sec = obj_datasec(abfd);
		case 'd':
			cached[i].symbol.flags = BSF_LOCAL;
			sec = obj_datasec(abfd);
		case 'B':
			cached[i].symbol.flags = BSF_GLOBAL;
			sec = obj_bsssec(abfd);
		case 'b':
			cached[i].symbol.flags = BSF_LOCAL;
			sec = obj_bsssec(abfd);
		}
		cached[i].symbol.value -= sec->vma;
	}

	obj_aout_symbols (abfd) = cached;
	free(syms);
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

