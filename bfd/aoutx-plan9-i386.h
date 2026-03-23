/* Plan 9 i386-specific a.out final-link overrides.  Initially copied from aoutx.h and modified.. */


#ifndef TABLE_SIZE
#define TABLE_SIZE(TABLE) (sizeof (TABLE) / sizeof (TABLE[0]))
#endif

//#define howto_table_std MY (std_howto_table)

// Moved from stage2.. 
#define MY_link_includes_lookup(table, string, create, copy) \
  ((struct MY (link_includes_entry) *) \
   bfd_hash_lookup (&(table)->root, (string), (create), (copy)))


#ifndef MY_final_link_relocate
#define MY_final_link_relocate _bfd_final_link_relocate
#endif

#ifndef MY_relocate_contents
#define MY_relocate_contents _bfd_relocate_contents
#endif



struct MY (final_link_info);
struct MY (link_includes_table);
struct MY (link_includes_entry);
struct MY (link_includes_totals);

/* Forward declarations for local Plan 9 a.out helpers.  */

static inline bfd_size_type
MY (add_to_stringtab) (bfd *abfd,
		       struct bfd_strtab_hash *tab,
		       const char *str,
		       bfd_boolean copy);

static INLINE asection *
MY (reloc_index_to_section) (bfd *abfd, int indx);

static bfd_boolean
MY (emit_stringtab) (bfd *abfd, struct bfd_strtab_hash *tab);

static bfd_boolean
MY (get_external_symbols) (bfd *abfd);

static bfd_boolean
MY (link_free_symbols) (bfd *abfd);

static bfd_boolean
MY (link_input_section_ext) (struct MY (final_link_info) *finfo,
			     bfd *input_bfd,
			     asection *input_section,
			     struct reloc_ext_external *relocs,
			     bfd_size_type rel_size,
			     bfd_byte *contents);

static bfd_boolean
MY (link_write_other_symbol) (struct aout_link_hash_entry *h, void *data);

static bfd_boolean
MY (link_input_section) (struct MY (final_link_info) *finfo,
			 bfd *input_bfd,
			 asection *input_section,
			 file_ptr *reloff_ptr,
			 bfd_size_type rel_size);

static bfd_boolean
MY (link_input_section_std) (struct MY (final_link_info) *finfo,
			     bfd *input_bfd,
			     asection *input_section,
			     struct reloc_std_external *relocs,
			     bfd_size_type rel_size,
			     bfd_byte *contents);

static bfd_boolean
MY (link_input_bfd) (struct MY (final_link_info) *finfo, bfd *input_bfd);











/*Start of AOUTX inclusions - stage2 */

/* During the final link step we need to pass around a bunch of
   information, so we do it in an instance of this structure family.  */

// Moved to top (of aoutx-plan9-i386.h)
//#define MY_link_includes_lookup(table, string, create, copy) \
//  ((struct MY (link_includes_entry) *) \
//   bfd_hash_lookup (&(table)->root, (string), (create), (copy)))

/* A hash table used for header files with N_BINCL entries.  */

//3394
struct MY (link_includes_table)
{
  struct bfd_hash_table root;
};

/* A linked list of totals that we have found for a particular header
   file.  */

//3402
struct MY (link_includes_totals)
{
  struct MY (link_includes_totals) *next;
  bfd_vma total;
};

/* An entry in the header file hash table.  */

//3411
struct MY (link_includes_entry)
{
  struct bfd_hash_entry root;
  /* List of totals we have found for this file.  */
  struct MY (link_includes_totals) *totals;
};

//3426
struct MY (final_link_info)
{
  /* General link information.  */
  struct bfd_link_info *info;
  /* Output bfd.  */
  bfd *output_bfd;
  /* Reloc file positions.  */
  file_ptr treloff, dreloff;
  /* File position of symbols.  */
  file_ptr symoff;
  /* String table.  */
  struct bfd_strtab_hash *strtab;
  /* Header file hash table.  */
  struct MY (link_includes_table) includes;
  /* A buffer large enough to hold the contents of any section.  */
  bfd_byte *contents;
  /* A buffer large enough to hold the relocs of any section.  */
  void * relocs;
  /* A buffer large enough to hold the symbol map of any input BFD.  */
  int *symbol_map;
  /* A buffer large enough to hold output symbols of any input BFD.  */
  struct external_nlist *output_syms;
};

/* The function to create a new entry in the header file hash table.  */

//3452
static struct bfd_hash_entry *
MY (link_includes_newfunc) (struct bfd_hash_entry *entry,
			    struct bfd_hash_table *table,
			    const char *string)
{
  struct MY (link_includes_entry) *ret =
    (struct MY (link_includes_entry) *) entry;

  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (ret == NULL)
    ret = bfd_hash_allocate (table, sizeof (* ret));
  if (ret == NULL)
    return NULL;

  /* Call the allocation method of the superclass.  */
  ret = ((struct MY (link_includes_entry) *)
	 bfd_hash_newfunc ((struct bfd_hash_entry *) ret, table, string));
  if (ret)
    {
      /* Set local fields.  */
      ret->totals = NULL;
    }

  return (struct bfd_hash_entry *) ret;
}

/* Write out a symbol that was not associated with an a.out input
   object.  */

//3482
static bfd_boolean
MY (link_write_other_symbol) (struct aout_link_hash_entry *h, void *data)
{
  struct MY (final_link_info) *finfo = (struct MY (final_link_info) *) data;
  bfd *output_bfd;
  int type;
  bfd_vma val;
  struct external_nlist outsym;
  bfd_size_type indx;
  bfd_size_type amt;

  if (h->root.type == bfd_link_hash_warning)
    {
      h = (struct aout_link_hash_entry *) h->root.u.i.link;
      if (h->root.type == bfd_link_hash_new)
	return TRUE;
    }

  output_bfd = finfo->output_bfd;

  if (aout_backend_info (output_bfd)->write_dynamic_symbol != NULL)
    {
      if (! ((*aout_backend_info (output_bfd)->write_dynamic_symbol)
	     (output_bfd, finfo->info, h)))
	{
	  /* FIXME: No way to handle errors.  */
	  abort ();
	}
    }

  if (h->written)
    return TRUE;

  h->written = TRUE;

  /* An indx of -2 means the symbol must be written.  */
  if (h->indx != -2
      && (finfo->info->strip == strip_all
	  || (finfo->info->strip == strip_some
	      && bfd_hash_lookup (finfo->info->keep_hash, h->root.root.string,
				  FALSE, FALSE) == NULL)))
    return TRUE;

  switch (h->root.type)
    {
    default:
    case bfd_link_hash_warning:
      abort ();
      /* Avoid variable not initialized warnings.  */
      return TRUE;
    case bfd_link_hash_new:
      /* This can happen for set symbols when sets are not being
         built.  */
      return TRUE;
    case bfd_link_hash_undefined:
      type = N_UNDF | N_EXT;
      val = 0;
      break;
    case bfd_link_hash_defined:
    case bfd_link_hash_defweak:
      {
	asection *sec;

	sec = h->root.u.def.section->output_section;
	BFD_ASSERT (bfd_is_abs_section (sec)
		    || sec->owner == output_bfd);
	if (sec == obj_textsec (output_bfd))
	  type = h->root.type == bfd_link_hash_defined ? N_TEXT : N_WEAKT;
	else if (sec == obj_datasec (output_bfd))
	  type = h->root.type == bfd_link_hash_defined ? N_DATA : N_WEAKD;
	else if (sec == obj_bsssec (output_bfd))
	  type = h->root.type == bfd_link_hash_defined ? N_BSS : N_WEAKB;
	else
	  type = h->root.type == bfd_link_hash_defined ? N_ABS : N_WEAKA;
	type |= N_EXT;
	val = (h->root.u.def.value
	       + sec->vma
	       + h->root.u.def.section->output_offset);
      }
      break;
    case bfd_link_hash_common:
      type = N_UNDF | N_EXT;
      val = h->root.u.c.size;
      break;
    case bfd_link_hash_undefweak:
      type = N_WEAKU;
      val = 0;
    case bfd_link_hash_indirect:
      /* We ignore these symbols, since the indirected symbol is
	 already in the hash table.  */
      return TRUE;
    }

  H_PUT_8 (output_bfd, type, outsym.e_type);
  H_PUT_8 (output_bfd, 0, outsym.e_other);
  H_PUT_16 (output_bfd, 0, outsym.e_desc);
  indx = MY (add_to_stringtab) (output_bfd, finfo->strtab, h->root.root.string,
			   FALSE);
  if (indx == - (bfd_size_type) 1)
    /* FIXME: No way to handle errors.  */
    abort ();

  PUT_WORD (output_bfd, indx, outsym.e_strx);
  PUT_WORD (output_bfd, val, outsym.e_value);

  amt = EXTERNAL_NLIST_SIZE;
  if (bfd_seek (output_bfd, finfo->symoff, SEEK_SET) != 0
      || bfd_bwrite ((void *) &outsym, amt, output_bfd) != amt)
    /* FIXME: No way to handle errors.  */
    abort ();

  finfo->symoff += EXTERNAL_NLIST_SIZE;
  h->indx = obj_aout_external_sym_count (output_bfd);
  ++obj_aout_external_sym_count (output_bfd);

  return TRUE;
}

/*End of AOUTX inclusions - stage2 */




/*Start of AOUTX inclusions - stage4 */
#ifndef howto_table_ext
#define howto_table_ext MY (ext_howto_table)
#endif

#ifndef howto_table_std
#define howto_table_std MY (std_howto_table)
#endif

reloc_howto_type plan9_i386_ext_howto_table[] =
{
  /*     Type         rs   size bsz  pcrel bitpos ovrf                  sf name          part_inpl readmask setmask pcdone.  */
  HOWTO (RELOC_8,       0,  0,  8,  FALSE, 0, complain_overflow_bitfield, 0, "8",           FALSE, 0, 0x000000ff, FALSE),
  HOWTO (RELOC_16,      0,  1, 	16, FALSE, 0, complain_overflow_bitfield, 0, "16",          FALSE, 0, 0x0000ffff, FALSE),
  HOWTO (RELOC_32,      0,  2, 	32, FALSE, 0, complain_overflow_bitfield, 0, "32",          FALSE, 0, 0xffffffff, FALSE),
  HOWTO (RELOC_DISP8,   0,  0, 	8,  TRUE,  0, complain_overflow_signed,   0, "DISP8", 	    FALSE, 0, 0x000000ff, FALSE),
  HOWTO (RELOC_DISP16,  0,  1, 	16, TRUE,  0, complain_overflow_signed,   0, "DISP16", 	    FALSE, 0, 0x0000ffff, FALSE),
  HOWTO (RELOC_DISP32,  0,  2, 	32, TRUE,  0, complain_overflow_signed,   0, "DISP32", 	    FALSE, 0, 0xffffffff, FALSE),
  HOWTO (RELOC_WDISP30, 2,  2, 	30, TRUE,  0, complain_overflow_signed,   0, "WDISP30",     FALSE, 0, 0x3fffffff, FALSE),
  HOWTO (RELOC_WDISP22, 2,  2, 	22, TRUE,  0, complain_overflow_signed,   0, "WDISP22",     FALSE, 0, 0x003fffff, FALSE),
  HOWTO (RELOC_HI22,   10,  2, 	22, FALSE, 0, complain_overflow_bitfield, 0, "HI22",	    FALSE, 0, 0x003fffff, FALSE),
  HOWTO (RELOC_22,      0,  2, 	22, FALSE, 0, complain_overflow_bitfield, 0, "22",          FALSE, 0, 0x003fffff, FALSE),
  HOWTO (RELOC_13,      0,  2, 	13, FALSE, 0, complain_overflow_bitfield, 0, "13",          FALSE, 0, 0x00001fff, FALSE),
  HOWTO (RELOC_LO10,    0,  2, 	10, FALSE, 0, complain_overflow_dont,     0, "LO10",        FALSE, 0, 0x000003ff, FALSE),
  HOWTO (RELOC_SFA_BASE,0,  2, 	32, FALSE, 0, complain_overflow_bitfield, 0, "SFA_BASE",    FALSE, 0, 0xffffffff, FALSE),
  HOWTO (RELOC_SFA_OFF13,0, 2, 	32, FALSE, 0, complain_overflow_bitfield, 0, "SFA_OFF13",   FALSE, 0, 0xffffffff, FALSE),
  HOWTO (RELOC_BASE10,  0,  2, 	10, FALSE, 0, complain_overflow_dont,     0, "BASE10",      FALSE, 0, 0x000003ff, FALSE),
  HOWTO (RELOC_BASE13,  0,  2,	13, FALSE, 0, complain_overflow_signed,   0, "BASE13",      FALSE, 0, 0x00001fff, FALSE),
  HOWTO (RELOC_BASE22, 10,  2,	22, FALSE, 0, complain_overflow_bitfield, 0, "BASE22",      FALSE, 0, 0x003fffff, FALSE),
  HOWTO (RELOC_PC10,    0,  2,	10, TRUE,  0, complain_overflow_dont,     0, "PC10",	    FALSE, 0, 0x000003ff, TRUE),
  HOWTO (RELOC_PC22,   10,  2,	22, TRUE,  0, complain_overflow_signed,   0, "PC22",  	    FALSE, 0, 0x003fffff, TRUE),
  HOWTO (RELOC_JMP_TBL, 2,  2, 	30, TRUE,  0, complain_overflow_signed,   0, "JMP_TBL",     FALSE, 0, 0x3fffffff, FALSE),
  HOWTO (RELOC_SEGOFF16,0,  2,	0,  FALSE, 0, complain_overflow_bitfield, 0, "SEGOFF16",    FALSE, 0, 0x00000000, FALSE),
  HOWTO (RELOC_GLOB_DAT,0,  2,	0,  FALSE, 0, complain_overflow_bitfield, 0, "GLOB_DAT",    FALSE, 0, 0x00000000, FALSE),
  HOWTO (RELOC_JMP_SLOT,0,  2,	0,  FALSE, 0, complain_overflow_bitfield, 0, "JMP_SLOT",    FALSE, 0, 0x00000000, FALSE),
  HOWTO (RELOC_RELATIVE,0,  2,	0,  FALSE, 0, complain_overflow_bitfield, 0, "RELATIVE",    FALSE, 0, 0x00000000, FALSE),
  HOWTO (0,             0,  0,  0,  FALSE, 0, complain_overflow_dont,     0, "R_SPARC_NONE",FALSE, 0, 0x00000000, TRUE),
  HOWTO (0,             0,  0,  0,  FALSE, 0, complain_overflow_dont,     0, "R_SPARC_NONE",FALSE, 0, 0x00000000, TRUE),
#define RELOC_SPARC_REV32 RELOC_WDISP19
  HOWTO (RELOC_SPARC_REV32, 0, 2, 32, FALSE, 0, complain_overflow_dont,   0,"R_SPARC_REV32",FALSE, 0, 0xffffffff, FALSE),
};

/* Convert standard reloc records to "arelent" format (incl byte swap).  */

reloc_howto_type plan9_i386_std_howto_table[] =
{
  /* type              rs size bsz  pcrel bitpos ovrf                     sf name     part_inpl readmask  setmask    pcdone.  */
HOWTO ( 0,	       0,  0,  	8,  FALSE, 0, complain_overflow_bitfield,0,"8",		TRUE, 0x000000ff,0x000000ff, FALSE),
HOWTO ( 1,	       0,  1, 	16, FALSE, 0, complain_overflow_bitfield,0,"16",	TRUE, 0x0000ffff,0x0000ffff, FALSE),
HOWTO ( 2,	       0,  2, 	32, FALSE, 0, complain_overflow_bitfield,0,"32",	TRUE, 0xffffffff,0xffffffff, FALSE),
HOWTO ( 3,	       0,  4, 	64, FALSE, 0, complain_overflow_bitfield,0,"64",	TRUE, 0xdeaddead,0xdeaddead, FALSE),
HOWTO ( 4,	       0,  0, 	8,  TRUE,  0, complain_overflow_signed,  0,"DISP8",	TRUE, 0x000000ff,0x000000ff, FALSE),
HOWTO ( 5,	       0,  1, 	16, TRUE,  0, complain_overflow_signed,  0,"DISP16",	TRUE, 0x0000ffff,0x0000ffff, FALSE),
HOWTO ( 6,	       0,  2, 	32, TRUE,  0, complain_overflow_signed,  0,"DISP32",	TRUE, 0xffffffff,0xffffffff, FALSE),
HOWTO ( 7,	       0,  4, 	64, TRUE,  0, complain_overflow_signed,  0,"DISP64",	TRUE, 0xfeedface,0xfeedface, FALSE),
HOWTO ( 8,	       0,  2,    0, FALSE, 0, complain_overflow_bitfield,0,"GOT_REL",	FALSE,         0,0x00000000, FALSE),
HOWTO ( 9,	       0,  1,   16, FALSE, 0, complain_overflow_bitfield,0,"BASE16",	FALSE,0xffffffff,0xffffffff, FALSE),
HOWTO (10,	       0,  2,   32, FALSE, 0, complain_overflow_bitfield,0,"BASE32",	FALSE,0xffffffff,0xffffffff, FALSE),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
  HOWTO (16,	       0,  2,	 0, FALSE, 0, complain_overflow_bitfield,0,"JMP_TABLE", FALSE,         0,0x00000000, FALSE),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
  HOWTO (32,	       0,  2,	 0, FALSE, 0, complain_overflow_bitfield,0,"RELATIVE",  FALSE,         0,0x00000000, FALSE),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
EMPTY_HOWTO (-1),
  HOWTO (40,	       0,  2,	 0, FALSE, 0, complain_overflow_bitfield,0,"BASEREL",   FALSE,         0,0x00000000, FALSE),
};

/*End of AOUTX inclusions - stage4 */











/*Start of AOUTX inclusions - stage5 */

//1775
static inline bfd_size_type
MY (add_to_stringtab) (bfd *abfd,
		       struct bfd_strtab_hash *tab,
		       const char *str,
		       bfd_boolean copy)
{
  bfd_boolean hash;
  bfd_size_type index;

  /* An index of 0 always means the empty string.  */
  if (str == 0 || *str == '\0')
    return 0;

  /* Don't hash if BFD_TRADITIONAL_FORMAT is set, because SunOS dbx
     doesn't understand a hashed string table.  */
  hash = TRUE;
  if ((abfd->flags & BFD_TRADITIONAL_FORMAT) != 0)
    hash = FALSE;

  index = _bfd_stringtab_add (tab, str, hash, copy);

  if (index != (bfd_size_type) -1)
    /* Add BYTES_IN_WORD to the return value to account for the
       space taken up by the string table size.  */
    index += BYTES_IN_WORD;

  return index;
}


//1807
static bfd_boolean
MY (emit_stringtab) (bfd *abfd, struct bfd_strtab_hash *tab)
{
  bfd_byte buffer[BYTES_IN_WORD];
  bfd_size_type amt = BYTES_IN_WORD;

  /* The string table starts with the size.  */
  PUT_WORD (abfd, _bfd_stringtab_size (tab) + BYTES_IN_WORD, buffer);
  if (bfd_bwrite ((void *) buffer, amt, abfd) != amt)
    return FALSE;

  return _bfd_stringtab_emit (abfd, tab);
}


//1268
static bfd_boolean
MY (get_external_symbols) (bfd *abfd)
{
  if (obj_aout_external_syms (abfd) == NULL)
    {
      bfd_size_type count;
      struct external_nlist *syms;
      bfd_size_type amt;

      count = exec_hdr (abfd)->a_syms / EXTERNAL_NLIST_SIZE;

#ifdef USE_MMAP
      if (! bfd_get_file_window (abfd, obj_sym_filepos (abfd),
				 exec_hdr (abfd)->a_syms,
				 &obj_aout_sym_window (abfd), TRUE))
	return FALSE;
      syms = (struct external_nlist *) obj_aout_sym_window (abfd).data;
#else
      /* We allocate using malloc to make the values easy to free
	 later on.  If we put them on the objalloc it might not be
	 possible to free them.  */
      syms = bfd_malloc (count * EXTERNAL_NLIST_SIZE);
      if (syms == NULL && count != 0)
	return FALSE;

      amt = exec_hdr (abfd)->a_syms;
      if (bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0
	  || bfd_bread (syms, amt, abfd) != amt)
	{
	  free (syms);
	  return FALSE;
	}
#endif

      obj_aout_external_syms (abfd) = syms;
      obj_aout_external_sym_count (abfd) = count;
    }

  if (obj_aout_external_strings (abfd) == NULL
      && exec_hdr (abfd)->a_syms != 0)
    {
      unsigned char string_chars[BYTES_IN_WORD];
      bfd_size_type stringsize;
      char *strings;
      bfd_size_type amt = BYTES_IN_WORD;

      /* Get the size of the strings.  */
      if (bfd_seek (abfd, obj_str_filepos (abfd), SEEK_SET) != 0
	  || bfd_bread ((void *) string_chars, amt, abfd) != amt)
	return FALSE;
      stringsize = GET_WORD (abfd, string_chars);

#ifdef USE_MMAP
      if (! bfd_get_file_window (abfd, obj_str_filepos (abfd), stringsize,
				 &obj_aout_string_window (abfd), TRUE))
	return FALSE;
      strings = (char *) obj_aout_string_window (abfd).data;
#else
      strings = bfd_malloc (stringsize + 1);
      if (strings == NULL)
	return FALSE;

      /* Skip space for the string count in the buffer for convenience
	 when using indexes.  */
      amt = stringsize - BYTES_IN_WORD;
      if (bfd_bread (strings + BYTES_IN_WORD, amt, abfd) != amt)
	{
	  free (strings);
	  return FALSE;
	}
#endif

      /* Ensure that a zero index yields an empty string.  */
      strings[0] = '\0';

      strings[stringsize - 1] = 0;

      obj_aout_external_strings (abfd) = strings;
      obj_aout_external_string_size (abfd) = stringsize;
    }

  return TRUE;
}


//3110
static bfd_boolean
MY (link_free_symbols) (bfd *abfd)
{
  if (obj_aout_external_syms (abfd) != NULL)
    {
#ifdef USE_MMAP
      bfd_free_window (&obj_aout_sym_window (abfd));
#else
      free ((void *) obj_aout_external_syms (abfd));
#endif
      obj_aout_external_syms (abfd) = NULL;
    }
  if (obj_aout_external_strings (abfd) != NULL)
    {
#ifdef USE_MMAP
      bfd_free_window (&obj_aout_string_window (abfd));
#else
      free ((void *) obj_aout_external_strings (abfd));
#endif
      obj_aout_external_strings (abfd) = NULL;
    }
  return TRUE;
}


//4186
static bfd_boolean
MY (link_input_section_ext) (struct MY (final_link_info) *finfo,
			     bfd *input_bfd,
			     asection *input_section,
			     struct reloc_ext_external *relocs,
			     bfd_size_type rel_size,
			     bfd_byte *contents)
{
  bfd_boolean (*check_dynamic_reloc)
    (struct bfd_link_info *, bfd *, asection *,
	     struct aout_link_hash_entry *, void *, bfd_byte *, bfd_boolean *,
	     bfd_vma *);
  bfd *output_bfd;
  bfd_boolean relocatable;
  struct external_nlist *syms;
  char *strings;
  struct aout_link_hash_entry **sym_hashes;
  int *symbol_map;
  bfd_size_type reloc_count;
  struct reloc_ext_external *rel;
  struct reloc_ext_external *rel_end;

  output_bfd = finfo->output_bfd;
  check_dynamic_reloc = aout_backend_info (output_bfd)->check_dynamic_reloc;

  BFD_ASSERT (obj_reloc_entry_size (input_bfd) == RELOC_EXT_SIZE);
  BFD_ASSERT (input_bfd->xvec->header_byteorder
	      == output_bfd->xvec->header_byteorder);

  relocatable = finfo->info->relocatable;
  syms = obj_aout_external_syms (input_bfd);
  strings = obj_aout_external_strings (input_bfd);
  sym_hashes = obj_aout_sym_hashes (input_bfd);
  symbol_map = finfo->symbol_map;

  reloc_count = rel_size / RELOC_EXT_SIZE;
  rel = relocs;
  rel_end = rel + reloc_count;
  for (; rel < rel_end; rel++)
    {
      bfd_vma r_addr;
      int r_index;
      int r_extern;
      unsigned int r_type;
      bfd_vma r_addend;
      struct aout_link_hash_entry *h = NULL;
      asection *r_section = NULL;
      bfd_vma relocation;

      r_addr = GET_SWORD (input_bfd, rel->r_address);

      if (bfd_header_big_endian (input_bfd))
	{
	  r_index  = (((unsigned int) rel->r_index[0] << 16)
		      | ((unsigned int) rel->r_index[1] << 8)
		      | rel->r_index[2]);
	  r_extern = (0 != (rel->r_type[0] & RELOC_EXT_BITS_EXTERN_BIG));
	  r_type   = ((rel->r_type[0] & RELOC_EXT_BITS_TYPE_BIG)
		      >> RELOC_EXT_BITS_TYPE_SH_BIG);
	}
      else
	{
	  r_index  = (((unsigned int) rel->r_index[2] << 16)
		      | ((unsigned int) rel->r_index[1] << 8)
		      | rel->r_index[0]);
	  r_extern = (0 != (rel->r_type[0] & RELOC_EXT_BITS_EXTERN_LITTLE));
	  r_type   = ((rel->r_type[0] & RELOC_EXT_BITS_TYPE_LITTLE)
		      >> RELOC_EXT_BITS_TYPE_SH_LITTLE);
	}

      r_addend = GET_SWORD (input_bfd, rel->r_addend);

      BFD_ASSERT (r_type < TABLE_SIZE (howto_table_ext));

      if (relocatable)
	{
	  /* We are generating a relocatable output file, and must
	     modify the reloc accordingly.  */
	  if (r_extern
	      || r_type == (unsigned int) RELOC_BASE10
	      || r_type == (unsigned int) RELOC_BASE13
	      || r_type == (unsigned int) RELOC_BASE22)
	    {
	      /* If we know the symbol this relocation is against,
		 convert it into a relocation against a section.  This
		 is what the native linker does.  */
	      if (r_type == (unsigned int) RELOC_BASE10
		  || r_type == (unsigned int) RELOC_BASE13
		  || r_type == (unsigned int) RELOC_BASE22)
		h = NULL;
	      else
		h = sym_hashes[r_index];
	      if (h != NULL
		  && (h->root.type == bfd_link_hash_defined
		      || h->root.type == bfd_link_hash_defweak))
		{
		  asection *output_section;

		  /* Change the r_extern value.  */
		  if (bfd_header_big_endian (output_bfd))
		    rel->r_type[0] &=~ RELOC_EXT_BITS_EXTERN_BIG;
		  else
		    rel->r_type[0] &=~ RELOC_EXT_BITS_EXTERN_LITTLE;

		  /* Compute a new r_index.  */
		  output_section = h->root.u.def.section->output_section;
		  if (output_section == obj_textsec (output_bfd))
		    r_index = N_TEXT;
		  else if (output_section == obj_datasec (output_bfd))
		    r_index = N_DATA;
		  else if (output_section == obj_bsssec (output_bfd))
		    r_index = N_BSS;
		  else
		    r_index = N_ABS;

		  /* Add the symbol value and the section VMA to the
		     addend.  */
		  relocation = (h->root.u.def.value
				+ output_section->vma
				+ h->root.u.def.section->output_offset);

		  /* Now RELOCATION is the VMA of the final
		     destination.  If this is a PC relative reloc,
		     then ADDEND is the negative of the source VMA.
		     We want to set ADDEND to the difference between
		     the destination VMA and the source VMA, which
		     means we must adjust RELOCATION by the change in
		     the source VMA.  This is done below.  */
		}
	      else
		{
		  /* We must change r_index according to the symbol
		     map.  */
		  r_index = symbol_map[r_index];

		  if (r_index == -1)
		    {
		      if (h != NULL)
			{
			  /* We decided to strip this symbol, but it
                             turns out that we can't.  Note that we
                             lose the other and desc information here.
                             I don't think that will ever matter for a
                             global symbol.  */
			  if (h->indx < 0)
			    {
			      h->indx = -2;
			      h->written = FALSE;
			      if (! MY (link_write_other_symbol) (h,
								  (void *) finfo))
				return FALSE;
			    }
			  r_index = h->indx;
			}
		      else
			{
			  const char *name;

			  name = strings + GET_WORD (input_bfd,
						     syms[r_index].e_strx);
			  if (! ((*finfo->info->callbacks->unattached_reloc)
				 (finfo->info, name, input_bfd, input_section,
				  r_addr)))
			    return FALSE;
			  r_index = 0;
			}
		    }

		  relocation = 0;

		  /* If this is a PC relative reloc, then the addend
		     is the negative of the source VMA.  We must
		     adjust it by the change in the source VMA.  This
		     is done below.  */
		}

	      /* Write out the new r_index value.  */
	      if (bfd_header_big_endian (output_bfd))
		{
		  rel->r_index[0] = r_index >> 16;
		  rel->r_index[1] = r_index >> 8;
		  rel->r_index[2] = r_index;
		}
	      else
		{
		  rel->r_index[2] = r_index >> 16;
		  rel->r_index[1] = r_index >> 8;
		  rel->r_index[0] = r_index;
		}
	    }
	  else
	    {
	      /* This is a relocation against a section.  We must
		 adjust by the amount that the section moved.  */
	      r_section = MY (reloc_index_to_section) (input_bfd, r_index);
	      relocation = (r_section->output_section->vma
			    + r_section->output_offset
			    - r_section->vma);

	      /* If this is a PC relative reloc, then the addend is
		 the difference in VMA between the destination and the
		 source.  We have just adjusted for the change in VMA
		 of the destination, so we must also adjust by the
		 change in VMA of the source.  This is done below.  */
	    }

	  /* As described above, we must always adjust a PC relative
	     reloc by the change in VMA of the source.  However, if
	     pcrel_offset is set, then the addend does not include the
	     location within the section, in which case we don't need
	     to adjust anything.  */
	  if (howto_table_ext[r_type].pc_relative
	      && ! howto_table_ext[r_type].pcrel_offset)
	    relocation -= (input_section->output_section->vma
			   + input_section->output_offset
			   - input_section->vma);

	  /* Change the addend if necessary.  */
	  if (relocation != 0)
	    PUT_WORD (output_bfd, r_addend + relocation, rel->r_addend);

	  /* Change the address of the relocation.  */
	  PUT_WORD (output_bfd,
		    r_addr + input_section->output_offset,
		    rel->r_address);
	}
      else
	{
	  bfd_boolean hundef;
	  bfd_reloc_status_type r;

	  /* We are generating an executable, and must do a full
	     relocation.  */
	  hundef = FALSE;

	  if (r_extern)
	    {
	      h = sym_hashes[r_index];

	      if (h != NULL
		  && (h->root.type == bfd_link_hash_defined
		      || h->root.type == bfd_link_hash_defweak))
		{
		  relocation = (h->root.u.def.value
				+ h->root.u.def.section->output_section->vma
				+ h->root.u.def.section->output_offset);
		}
	      else if (h != NULL
		       && h->root.type == bfd_link_hash_undefweak)
		relocation = 0;
	      else
		{
		  hundef = TRUE;
		  relocation = 0;
		}
	    }
	  else if (r_type == (unsigned int) RELOC_BASE10
		   || r_type == (unsigned int) RELOC_BASE13
		   || r_type == (unsigned int) RELOC_BASE22)
	    {
	      struct external_nlist *sym;
	      int type;

	      /* For base relative relocs, r_index is always an index
                 into the symbol table, even if r_extern is 0.  */
	      sym = syms + r_index;
	      type = H_GET_8 (input_bfd, sym->e_type);
	      if ((type & N_TYPE) == N_TEXT
		  || type == N_WEAKT)
		r_section = obj_textsec (input_bfd);
	      else if ((type & N_TYPE) == N_DATA
		       || type == N_WEAKD)
		r_section = obj_datasec (input_bfd);
	      else if ((type & N_TYPE) == N_BSS
		       || type == N_WEAKB)
		r_section = obj_bsssec (input_bfd);
	      else if ((type & N_TYPE) == N_ABS
		       || type == N_WEAKA)
		r_section = bfd_abs_section_ptr;
	      else
		abort ();
	      relocation = (r_section->output_section->vma
			    + r_section->output_offset
			    + (GET_WORD (input_bfd, sym->e_value)
			       - r_section->vma));
	    }
	  else
	    {
	      r_section = MY (reloc_index_to_section) (input_bfd, r_index);

	      /* If this is a PC relative reloc, then R_ADDEND is the
		 difference between the two vmas, or
		   old_dest_sec + old_dest_off - (old_src_sec + old_src_off)
		 where
		   old_dest_sec == section->vma
		 and
		   old_src_sec == input_section->vma
		 and
		   old_src_off == r_addr

		 _bfd_final_link_relocate expects RELOCATION +
		 R_ADDEND to be the VMA of the destination minus
		 r_addr (the minus r_addr is because this relocation
		 is not pcrel_offset, which is a bit confusing and
		 should, perhaps, be changed), or
		   new_dest_sec
		 where
		   new_dest_sec == output_section->vma + output_offset
		 We arrange for this to happen by setting RELOCATION to
		   new_dest_sec + old_src_sec - old_dest_sec

		 If this is not a PC relative reloc, then R_ADDEND is
		 simply the VMA of the destination, so we set
		 RELOCATION to the change in the destination VMA, or
		   new_dest_sec - old_dest_sec
		 */
	      relocation = (r_section->output_section->vma
			    + r_section->output_offset
			    - r_section->vma);
	      if (howto_table_ext[r_type].pc_relative)
		relocation += input_section->vma;
	    }

	  if (check_dynamic_reloc != NULL)
	    {
	      bfd_boolean skip;

	      if (! ((*check_dynamic_reloc)
		     (finfo->info, input_bfd, input_section, h,
		      (void *) rel, contents, &skip, &relocation)))
		return FALSE;
	      if (skip)
		continue;
	    }

	  /* Now warn if a global symbol is undefined.  We could not
             do this earlier, because check_dynamic_reloc might want
             to skip this reloc.  */
	  if (hundef
	      && ! finfo->info->shared
	      && r_type != (unsigned int) RELOC_BASE10
	      && r_type != (unsigned int) RELOC_BASE13
	      && r_type != (unsigned int) RELOC_BASE22)
	    {
	      const char *name;

	      if (h != NULL)
		name = h->root.root.string;
	      else
		name = strings + GET_WORD (input_bfd, syms[r_index].e_strx);
	      if (! ((*finfo->info->callbacks->undefined_symbol)
		     (finfo->info, name, input_bfd, input_section,
		     r_addr, TRUE)))
		return FALSE;
	    }

	  if (r_type != (unsigned int) RELOC_SPARC_REV32)
	    r = MY_final_link_relocate (howto_table_ext + r_type,
					input_bfd, input_section,
					contents, r_addr, relocation,
					r_addend);
	  else
	    {
	      bfd_vma x;

	      x = bfd_get_32 (input_bfd, contents + r_addr);
	      x = x + relocation + r_addend;
	      bfd_putl32 (/*input_bfd,*/ x, contents + r_addr);
	      r = bfd_reloc_ok;
	    }

	  if (r != bfd_reloc_ok)
	    {
	      switch (r)
		{
		default:
		case bfd_reloc_outofrange:
		  abort ();
		case bfd_reloc_overflow:
		  {
		    const char *name;

		    if (h != NULL)
		      name = NULL;
		    else if (r_extern
			     || r_type == (unsigned int) RELOC_BASE10
			     || r_type == (unsigned int) RELOC_BASE13
			     || r_type == (unsigned int) RELOC_BASE22)
		      name = strings + GET_WORD (input_bfd,
						 syms[r_index].e_strx);
		    else
		      {
			asection *s;

			s = MY (reloc_index_to_section) (input_bfd, r_index);
			name = bfd_section_name (input_bfd, s);
		      }
		    if (! ((*finfo->info->callbacks->reloc_overflow)
			   (finfo->info, (h ? &h->root : NULL), name,
			    howto_table_ext[r_type].name,
			    r_addend, input_bfd, input_section, r_addr)))
		      return FALSE;
		  }
		  break;
		}
	    }
	}
    }

  return TRUE;
}

/*End of AOUTX inclusions - stage5 */












/*Start of AOUTX inclusions - stage3 */

//4681-5160
static bfd_boolean
MY (link_write_symbols) (struct MY (final_link_info) *finfo, bfd *input_bfd)
{
  bfd *output_bfd;
  bfd_size_type sym_count;
  char *strings;
  enum bfd_link_strip strip;
  enum bfd_link_discard discard;
  struct external_nlist *outsym;
  bfd_size_type strtab_index;
  struct external_nlist *sym;
  struct external_nlist *sym_end;
  struct aout_link_hash_entry **sym_hash;
  int *symbol_map;
  bfd_boolean pass;
  bfd_boolean skip_next;

  output_bfd = finfo->output_bfd;
  sym_count = obj_aout_external_sym_count (input_bfd);
  strings = obj_aout_external_strings (input_bfd);
  strip = finfo->info->strip;
  discard = finfo->info->discard;
  outsym = finfo->output_syms;

  /* First write out a symbol for this object file, unless we are
     discarding such symbols.  */
  if (strip != strip_all
      && (strip != strip_some
	  || bfd_hash_lookup (finfo->info->keep_hash, input_bfd->filename,
			      FALSE, FALSE) != NULL)
      && discard != discard_all)
    {
      H_PUT_8 (output_bfd, N_TEXT, outsym->e_type);
      H_PUT_8 (output_bfd, 0, outsym->e_other);
      H_PUT_16 (output_bfd, 0, outsym->e_desc);
      strtab_index = MY (add_to_stringtab) (output_bfd, finfo->strtab,
				       input_bfd->filename, FALSE);
      if (strtab_index == (bfd_size_type) -1)
	return FALSE;
      PUT_WORD (output_bfd, strtab_index, outsym->e_strx);
      PUT_WORD (output_bfd,
		(bfd_get_section_vma (output_bfd,
				      obj_textsec (input_bfd)->output_section)
		 + obj_textsec (input_bfd)->output_offset),
		outsym->e_value);
      ++obj_aout_external_sym_count (output_bfd);
      ++outsym;
    }

  pass = FALSE;
  skip_next = FALSE;
  sym = obj_aout_external_syms (input_bfd);
  sym_end = sym + sym_count;
  sym_hash = obj_aout_sym_hashes (input_bfd);
  symbol_map = finfo->symbol_map;
  memset (symbol_map, 0, (size_t) sym_count * sizeof *symbol_map);
  for (; sym < sym_end; sym++, sym_hash++, symbol_map++)
    {
      const char *name;
      int type;
      struct aout_link_hash_entry *h;
      bfd_boolean skip;
      asection *symsec;
      bfd_vma val = 0;
      bfd_boolean copy;

      /* We set *symbol_map to 0 above for all symbols.  If it has
         already been set to -1 for this symbol, it means that we are
         discarding it because it appears in a duplicate header file.
         See the N_BINCL code below.  */
      if (*symbol_map == -1)
	continue;

      /* Initialize *symbol_map to -1, which means that the symbol was
         not copied into the output file.  We will change it later if
         we do copy the symbol over.  */
      *symbol_map = -1;

      type = H_GET_8 (input_bfd, sym->e_type);
      name = strings + GET_WORD (input_bfd, sym->e_strx);

      h = NULL;

      if (pass)
	{
	  /* Pass this symbol through.  It is the target of an
	     indirect or warning symbol.  */
	  val = GET_WORD (input_bfd, sym->e_value);
	  pass = FALSE;
	}
      else if (skip_next)
	{
	  /* Skip this symbol, which is the target of an indirect
	     symbol that we have changed to no longer be an indirect
	     symbol.  */
	  skip_next = FALSE;
	  continue;
	}
      else
	{
	  struct aout_link_hash_entry *hresolve;

	  /* We have saved the hash table entry for this symbol, if
	     there is one.  Note that we could just look it up again
	     in the hash table, provided we first check that it is an
	     external symbol.  */
	  h = *sym_hash;

	  /* Use the name from the hash table, in case the symbol was
             wrapped.  */
	  if (h != NULL
	      && h->root.type != bfd_link_hash_warning)
	    name = h->root.root.string;

	  /* If this is an indirect or warning symbol, then change
	     hresolve to the base symbol.  We also change *sym_hash so
	     that the relocation routines relocate against the real
	     symbol.  */
	  hresolve = h;
	  if (h != (struct aout_link_hash_entry *) NULL
	      && (h->root.type == bfd_link_hash_indirect
		  || h->root.type == bfd_link_hash_warning))
	    {
	      hresolve = (struct aout_link_hash_entry *) h->root.u.i.link;
	      while (hresolve->root.type == bfd_link_hash_indirect
		     || hresolve->root.type == bfd_link_hash_warning)
		hresolve = ((struct aout_link_hash_entry *)
			    hresolve->root.u.i.link);
	      *sym_hash = hresolve;
	    }

	  /* If the symbol has already been written out, skip it.  */
	  if (h != NULL
	      && h->written)
	    {
	      if ((type & N_TYPE) == N_INDR
		  || type == N_WARNING)
		skip_next = TRUE;
	      *symbol_map = h->indx;
	      continue;
	    }

	  /* See if we are stripping this symbol.  */
	  skip = FALSE;
	  switch (strip)
	    {
	    case strip_none:
	      break;
	    case strip_debugger:
	      if ((type & N_STAB) != 0)
		skip = TRUE;
	      break;
	    case strip_some:
	      if (bfd_hash_lookup (finfo->info->keep_hash, name, FALSE, FALSE)
		  == NULL)
		skip = TRUE;
	      break;
	    case strip_all:
	      skip = TRUE;
	      break;
	    }
	  if (skip)
	    {
	      if (h != NULL)
		h->written = TRUE;
	      continue;
	    }

	  /* Get the value of the symbol.  */
	  if ((type & N_TYPE) == N_TEXT
	      || type == N_WEAKT)
	    symsec = obj_textsec (input_bfd);
	  else if ((type & N_TYPE) == N_DATA
		   || type == N_WEAKD)
	    symsec = obj_datasec (input_bfd);
	  else if ((type & N_TYPE) == N_BSS
		   || type == N_WEAKB)
	    symsec = obj_bsssec (input_bfd);
	  else if ((type & N_TYPE) == N_ABS
		   || type == N_WEAKA)
	    symsec = bfd_abs_section_ptr;
	  else if (((type & N_TYPE) == N_INDR
		    && (hresolve == NULL
			|| (hresolve->root.type != bfd_link_hash_defined
			    && hresolve->root.type != bfd_link_hash_defweak
			    && hresolve->root.type != bfd_link_hash_common)))
		   || type == N_WARNING)
	    {
	      /* Pass the next symbol through unchanged.  The
		 condition above for indirect symbols is so that if
		 the indirect symbol was defined, we output it with
		 the correct definition so the debugger will
		 understand it.  */
	      pass = TRUE;
	      val = GET_WORD (input_bfd, sym->e_value);
	      symsec = NULL;
	    }
	  else if ((type & N_STAB) != 0)
	    {
	      val = GET_WORD (input_bfd, sym->e_value);
	      symsec = NULL;
	    }
	  else
	    {
	      /* If we get here with an indirect symbol, it means that
		 we are outputting it with a real definition.  In such
		 a case we do not want to output the next symbol,
		 which is the target of the indirection.  */
	      if ((type & N_TYPE) == N_INDR)
		skip_next = TRUE;

	      symsec = NULL;

	      /* We need to get the value from the hash table.  We use
		 hresolve so that if we have defined an indirect
		 symbol we output the final definition.  */
	      if (h == NULL)
		{
		  switch (type & N_TYPE)
		    {
		    case N_SETT:
		      symsec = obj_textsec (input_bfd);
		      break;
		    case N_SETD:
		      symsec = obj_datasec (input_bfd);
		      break;
		    case N_SETB:
		      symsec = obj_bsssec (input_bfd);
		      break;
		    case N_SETA:
		      symsec = bfd_abs_section_ptr;
		      break;
		    default:
		      val = 0;
		      break;
		    }
		}
	      else if (hresolve->root.type == bfd_link_hash_defined
		       || hresolve->root.type == bfd_link_hash_defweak)
		{
		  asection *input_section;
		  asection *output_section;

		  /* This case usually means a common symbol which was
		     turned into a defined symbol.  */
		  input_section = hresolve->root.u.def.section;
		  output_section = input_section->output_section;
		  BFD_ASSERT (bfd_is_abs_section (output_section)
			      || output_section->owner == output_bfd);
		  val = (hresolve->root.u.def.value
			 + bfd_get_section_vma (output_bfd, output_section)
			 + input_section->output_offset);

		  /* Get the correct type based on the section.  If
		     this is a constructed set, force it to be
		     globally visible.  */
		  if (type == N_SETT
		      || type == N_SETD
		      || type == N_SETB
		      || type == N_SETA)
		    type |= N_EXT;

		  type &=~ N_TYPE;

		  if (output_section == obj_textsec (output_bfd))
		    type |= (hresolve->root.type == bfd_link_hash_defined
			     ? N_TEXT
			     : N_WEAKT);
		  else if (output_section == obj_datasec (output_bfd))
		    type |= (hresolve->root.type == bfd_link_hash_defined
			     ? N_DATA
			     : N_WEAKD);
		  else if (output_section == obj_bsssec (output_bfd))
		    type |= (hresolve->root.type == bfd_link_hash_defined
			     ? N_BSS
			     : N_WEAKB);
		  else
		    type |= (hresolve->root.type == bfd_link_hash_defined
			     ? N_ABS
			     : N_WEAKA);
		}
	      else if (hresolve->root.type == bfd_link_hash_common)
		val = hresolve->root.u.c.size;
	      else if (hresolve->root.type == bfd_link_hash_undefweak)
		{
		  val = 0;
		  type = N_WEAKU;
		}
	      else
		val = 0;
	    }
	  if (symsec != NULL)
	    val = (symsec->output_section->vma
		   + symsec->output_offset
		   + (GET_WORD (input_bfd, sym->e_value)
		      - symsec->vma));

	  /* If this is a global symbol set the written flag, and if
	     it is a local symbol see if we should discard it.  */
	  if (h != NULL)
	    {
	      h->written = TRUE;
	      h->indx = obj_aout_external_sym_count (output_bfd);
	    }
	  else if ((type & N_TYPE) != N_SETT
		   && (type & N_TYPE) != N_SETD
		   && (type & N_TYPE) != N_SETB
		   && (type & N_TYPE) != N_SETA)
	    {
	      switch (discard)
		{
		case discard_none:
		case discard_sec_merge:
		  break;
		case discard_l:
		  if ((type & N_STAB) == 0
		      && bfd_is_local_label_name (input_bfd, name))
		    skip = TRUE;
		  break;
		case discard_all:
		  skip = TRUE;
		  break;
		}
	      if (skip)
		{
		  pass = FALSE;
		  continue;
		}
	    }

	  /* An N_BINCL symbol indicates the start of the stabs
	     entries for a header file.  We need to scan ahead to the
	     next N_EINCL symbol, ignoring nesting, adding up all the
	     characters in the symbol names, not including the file
	     numbers in types (the first number after an open
	     parenthesis).  */
	  if (type == (int) N_BINCL)
	    {
	      struct external_nlist *incl_sym;
	      int nest;
	      struct MY (link_includes_entry) *incl_entry;
	      struct MY (link_includes_totals) *t;

	      val = 0;
	      nest = 0;
	      for (incl_sym = sym + 1; incl_sym < sym_end; incl_sym++)
		{
		  int incl_type;

		  incl_type = H_GET_8 (input_bfd, incl_sym->e_type);
		  if (incl_type == (int) N_EINCL)
		    {
		      if (nest == 0)
			break;
		      --nest;
		    }
		  else if (incl_type == (int) N_BINCL)
		    ++nest;
		  else if (nest == 0)
		    {
		      const char *s;

		      s = strings + GET_WORD (input_bfd, incl_sym->e_strx);
		      for (; *s != '\0'; s++)
			{
			  val += *s;
			  if (*s == '(')
			    {
			      /* Skip the file number.  */
			      ++s;
			      while (ISDIGIT (*s))
				++s;
			      --s;
			    }
			}
		    }
		}

	      /* If we have already included a header file with the
                 same value, then replace this one with an N_EXCL
                 symbol.  */
	      copy = (bfd_boolean) (! finfo->info->keep_memory);
	      incl_entry = MY_link_includes_lookup (&finfo->includes,
						    name, TRUE, copy);
	      if (incl_entry == NULL)
		return FALSE;
	      for (t = incl_entry->totals; t != NULL; t = t->next)
		if (t->total == val)
		  break;
	      if (t == NULL)
		{
		  /* This is the first time we have seen this header
                     file with this set of stabs strings.  */
		  t = bfd_hash_allocate (&finfo->includes.root,
					 sizeof *t);
		  if (t == NULL)
		    return FALSE;
		  t->total = val;
		  t->next = incl_entry->totals;
		  incl_entry->totals = t;
		}
	      else
		{
		  int *incl_map;

		  /* This is a duplicate header file.  We must change
                     it to be an N_EXCL entry, and mark all the
                     included symbols to prevent outputting them.  */
		  type = (int) N_EXCL;

		  nest = 0;
		  for (incl_sym = sym + 1, incl_map = symbol_map + 1;
		       incl_sym < sym_end;
		       incl_sym++, incl_map++)
		    {
		      int incl_type;

		      incl_type = H_GET_8 (input_bfd, incl_sym->e_type);
		      if (incl_type == (int) N_EINCL)
			{
			  if (nest == 0)
			    {
			      *incl_map = -1;
			      break;
			    }
			  --nest;
			}
		      else if (incl_type == (int) N_BINCL)
			++nest;
		      else if (nest == 0)
			*incl_map = -1;
		    }
		}
	    }
	}

      /* Copy this symbol into the list of symbols we are going to
	 write out.  */
      H_PUT_8 (output_bfd, type, outsym->e_type);
      H_PUT_8 (output_bfd, H_GET_8 (input_bfd, sym->e_other), outsym->e_other);
      H_PUT_16 (output_bfd, H_GET_16 (input_bfd, sym->e_desc), outsym->e_desc);
      copy = FALSE;
      if (! finfo->info->keep_memory)
	{
	  /* name points into a string table which we are going to
	     free.  If there is a hash table entry, use that string.
	     Otherwise, copy name into memory.  */
	  if (h != NULL)
	    name = h->root.root.string;
	  else
	    copy = TRUE;
	}
      strtab_index = MY (add_to_stringtab) (output_bfd, finfo->strtab,
				       name, copy);
      if (strtab_index == (bfd_size_type) -1)
	return FALSE;
      PUT_WORD (output_bfd, strtab_index, outsym->e_strx);
      PUT_WORD (output_bfd, val, outsym->e_value);
      *symbol_map = obj_aout_external_sym_count (output_bfd);
      ++obj_aout_external_sym_count (output_bfd);
      ++outsym;
    }

  /* Write out the output symbols we have just constructed.  */
  if (outsym > finfo->output_syms)
    {
      bfd_size_type outsym_size;

      if (bfd_seek (output_bfd, finfo->symoff, SEEK_SET) != 0)
	return FALSE;
      outsym_size = outsym - finfo->output_syms;
      outsym_size *= EXTERNAL_NLIST_SIZE;
      if (bfd_bwrite ((void *) finfo->output_syms, outsym_size, output_bfd)
	  != outsym_size)
	return FALSE;
      finfo->symoff += outsym_size;
    }

  return TRUE;
}

//3602-3821
static bfd_boolean
MY (link_reloc_link_order) (struct MY (final_link_info) *finfo,
			    asection *o,
			    struct bfd_link_order *p)
{
  struct bfd_link_order_reloc *pr;
  int r_index;
  int r_extern;
  reloc_howto_type *howto;
  file_ptr *reloff_ptr = NULL;
  struct reloc_std_external srel;
  struct reloc_ext_external erel;
  void * rel_ptr;
  bfd_size_type amt;

  pr = p->u.reloc.p;

  if (p->type == bfd_section_reloc_link_order)
    {
      r_extern = 0;
      if (bfd_is_abs_section (pr->u.section))
	r_index = N_ABS | N_EXT;
      else
	{
	  BFD_ASSERT (pr->u.section->owner == finfo->output_bfd);
	  r_index = pr->u.section->target_index;
	}
    }
  else
    {
      struct aout_link_hash_entry *h;

      BFD_ASSERT (p->type == bfd_symbol_reloc_link_order);
      r_extern = 1;
      h = ((struct aout_link_hash_entry *)
	   bfd_wrapped_link_hash_lookup (finfo->output_bfd, finfo->info,
					 pr->u.name, FALSE, FALSE, TRUE));
      if (h != NULL
	  && h->indx >= 0)
	r_index = h->indx;
      else if (h != NULL)
	{
	  /* We decided to strip this symbol, but it turns out that we
	     can't.  Note that we lose the other and desc information
	     here.  I don't think that will ever matter for a global
	     symbol.  */
	  h->indx = -2;
	  h->written = FALSE;
	  if (! MY (link_write_other_symbol) (h, (void *) finfo))
	    return FALSE;
	  r_index = h->indx;
	}
      else
	{
	  if (! ((*finfo->info->callbacks->unattached_reloc)
		 (finfo->info, pr->u.name, NULL, NULL, (bfd_vma) 0)))
	    return FALSE;
	  r_index = 0;
	}
    }

  howto = bfd_reloc_type_lookup (finfo->output_bfd, pr->reloc);
  if (howto == 0)
    {
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }

  if (o == obj_textsec (finfo->output_bfd))
    reloff_ptr = &finfo->treloff;
  else if (o == obj_datasec (finfo->output_bfd))
    reloff_ptr = &finfo->dreloff;
  else
    abort ();

  if (obj_reloc_entry_size (finfo->output_bfd) == RELOC_STD_SIZE)
    {
#ifdef MY_put_reloc
      MY_put_reloc (finfo->output_bfd, r_extern, r_index, p->offset, howto,
		    &srel);
#else
      {
	int r_pcrel;
	int r_baserel;
	int r_jmptable;
	int r_relative;
	int r_length;

	r_pcrel = (int) howto->pc_relative;
	r_baserel = (howto->type & 8) != 0;
	r_jmptable = (howto->type & 16) != 0;
	r_relative = (howto->type & 32) != 0;
	r_length = howto->size;

	PUT_WORD (finfo->output_bfd, p->offset, srel.r_address);
	if (bfd_header_big_endian (finfo->output_bfd))
	  {
	    srel.r_index[0] = r_index >> 16;
	    srel.r_index[1] = r_index >> 8;
	    srel.r_index[2] = r_index;
	    srel.r_type[0] =
	      ((r_extern ?     RELOC_STD_BITS_EXTERN_BIG : 0)
	       | (r_pcrel ?    RELOC_STD_BITS_PCREL_BIG : 0)
	       | (r_baserel ?  RELOC_STD_BITS_BASEREL_BIG : 0)
	       | (r_jmptable ? RELOC_STD_BITS_JMPTABLE_BIG : 0)
	       | (r_relative ? RELOC_STD_BITS_RELATIVE_BIG : 0)
	       | (r_length <<  RELOC_STD_BITS_LENGTH_SH_BIG));
	  }
	else
	  {
	    srel.r_index[2] = r_index >> 16;
	    srel.r_index[1] = r_index >> 8;
	    srel.r_index[0] = r_index;
	    srel.r_type[0] =
	      ((r_extern ?     RELOC_STD_BITS_EXTERN_LITTLE : 0)
	       | (r_pcrel ?    RELOC_STD_BITS_PCREL_LITTLE : 0)
	       | (r_baserel ?  RELOC_STD_BITS_BASEREL_LITTLE : 0)
	       | (r_jmptable ? RELOC_STD_BITS_JMPTABLE_LITTLE : 0)
	       | (r_relative ? RELOC_STD_BITS_RELATIVE_LITTLE : 0)
	       | (r_length <<  RELOC_STD_BITS_LENGTH_SH_LITTLE));
	  }
      }
#endif
      rel_ptr = (void *) &srel;

      /* We have to write the addend into the object file, since
	 standard a.out relocs are in place.  It would be more
	 reliable if we had the current contents of the file here,
	 rather than assuming zeroes, but we can't read the file since
	 it was opened using bfd_openw.  */
      if (pr->addend != 0)
	{
	  bfd_size_type size;
	  bfd_reloc_status_type r;
	  bfd_byte *buf;
	  bfd_boolean ok;

	  size = bfd_get_reloc_size (howto);
	  buf = bfd_zmalloc (size);
	  if (buf == NULL)
	    return FALSE;
	  r = MY_relocate_contents (howto, finfo->output_bfd,
				    (bfd_vma) pr->addend, buf);
	  switch (r)
	    {
	    case bfd_reloc_ok:
	      break;
	    default:
	    case bfd_reloc_outofrange:
	      abort ();
	    case bfd_reloc_overflow:
	      if (! ((*finfo->info->callbacks->reloc_overflow)
		     (finfo->info, NULL,
		      (p->type == bfd_section_reloc_link_order
		       ? bfd_section_name (finfo->output_bfd,
					   pr->u.section)
		       : pr->u.name),
		      howto->name, pr->addend, NULL, NULL, (bfd_vma) 0)))
		{
		  free (buf);
		  return FALSE;
		}
	      break;
	    }
	  ok = bfd_set_section_contents (finfo->output_bfd, o, (void *) buf,
					 (file_ptr) p->offset, size);
	  free (buf);
	  if (! ok)
	    return FALSE;
	}
    }
  else
    {
#ifdef MY_put_ext_reloc
      MY_put_ext_reloc (finfo->output_bfd, r_extern, r_index, p->offset,
			howto, &erel, pr->addend);
#else
      PUT_WORD (finfo->output_bfd, p->offset, erel.r_address);

      if (bfd_header_big_endian (finfo->output_bfd))
	{
	  erel.r_index[0] = r_index >> 16;
	  erel.r_index[1] = r_index >> 8;
	  erel.r_index[2] = r_index;
	  erel.r_type[0] =
	    ((r_extern ? RELOC_EXT_BITS_EXTERN_BIG : 0)
	     | (howto->type << RELOC_EXT_BITS_TYPE_SH_BIG));
	}
      else
	{
	  erel.r_index[2] = r_index >> 16;
	  erel.r_index[1] = r_index >> 8;
	  erel.r_index[0] = r_index;
	  erel.r_type[0] =
	    (r_extern ? RELOC_EXT_BITS_EXTERN_LITTLE : 0)
	      | (howto->type << RELOC_EXT_BITS_TYPE_SH_LITTLE);
	}

      PUT_WORD (finfo->output_bfd, (bfd_vma) pr->addend, erel.r_addend);
#endif /* MY_put_ext_reloc */

      rel_ptr = (void *) &erel;
    }

  amt = obj_reloc_entry_size (finfo->output_bfd);
  if (bfd_seek (finfo->output_bfd, *reloff_ptr, SEEK_SET) != 0
      || bfd_bwrite (rel_ptr, amt, finfo->output_bfd) != amt)
    return FALSE;

  *reloff_ptr += obj_reloc_entry_size (finfo->output_bfd);

  /* Assert that the relocs have not run into the symbols, and that n
     the text relocs have not run into the data relocs.  */
  BFD_ASSERT (*reloff_ptr <= obj_sym_filepos (finfo->output_bfd)
	      && (reloff_ptr != &finfo->treloff
		  || (*reloff_ptr
		      <= obj_datasec (finfo->output_bfd)->rel_filepos)));

  return TRUE;
}


/*End of AOUTX inclusions - stage3 */












// From bfd/aoutx.h:3825
static INLINE asection *
MY (reloc_index_to_section) (bfd *abfd, int indx)
{
  switch (indx & N_TYPE)
    {
    case N_TEXT:   return obj_textsec (abfd);
    case N_DATA:   return obj_datasec (abfd);
    case N_BSS:    return obj_bsssec (abfd);
    case N_ABS:
    case N_UNDF:   return bfd_abs_section_ptr;
    default:       abort ();
    }
  return NULL;
}

// From bfd/aoutx.h:3842
static bfd_boolean
MY (link_input_section_std) (struct MY (final_link_info) *finfo,
			     bfd *input_bfd,
			     asection *input_section,
			     struct reloc_std_external *relocs,
			     bfd_size_type rel_size,
			     bfd_byte *contents)
{

  bfd_boolean (*check_dynamic_reloc)
    (struct bfd_link_info *, bfd *, asection *,
     struct aout_link_hash_entry *, void *, bfd_byte *, bfd_boolean *,
     bfd_vma *);
  bfd *output_bfd;
  bfd_boolean relocatable;
  struct external_nlist *syms;
  char *strings;
  struct aout_link_hash_entry **sym_hashes;
  int *symbol_map;
  bfd_size_type reloc_count;
  struct reloc_std_external *rel;
  struct reloc_std_external *rel_end;

  output_bfd = finfo->output_bfd;
  check_dynamic_reloc = aout_backend_info (output_bfd)->check_dynamic_reloc;

  BFD_ASSERT (obj_reloc_entry_size (input_bfd) == RELOC_STD_SIZE);
  BFD_ASSERT (input_bfd->xvec->header_byteorder
	      == output_bfd->xvec->header_byteorder);

  relocatable = finfo->info->relocatable;
  syms = obj_aout_external_syms (input_bfd);
  strings = obj_aout_external_strings (input_bfd);
  sym_hashes = obj_aout_sym_hashes (input_bfd);
  symbol_map = finfo->symbol_map;

  reloc_count = rel_size / RELOC_STD_SIZE;
  rel = relocs;
  rel_end = rel + reloc_count;
  for (; rel < rel_end; rel++)
    {
      bfd_vma r_addr;
      int r_index;
      int r_extern;
      int r_pcrel;
      int r_baserel = 0;
      reloc_howto_type *howto;
      struct aout_link_hash_entry *h = NULL;
      bfd_vma relocation;
      bfd_reloc_status_type r;

      r_addr = GET_SWORD (input_bfd, rel->r_address);

#ifdef MY_reloc_howto
      howto = MY_reloc_howto (input_bfd, rel, r_index, r_extern, r_pcrel);
#else
      {
	int r_jmptable;
	int r_relative;
	int r_length;
	unsigned int howto_idx;

	if (bfd_header_big_endian (input_bfd))
	  {
	    r_index   = (((unsigned int) rel->r_index[0] << 16)
			 | ((unsigned int) rel->r_index[1] << 8)
			 | rel->r_index[2]);
	    r_extern  = (0 != (rel->r_type[0] & RELOC_STD_BITS_EXTERN_BIG));
	    r_pcrel   = (0 != (rel->r_type[0] & RELOC_STD_BITS_PCREL_BIG));
	    r_baserel = (0 != (rel->r_type[0] & RELOC_STD_BITS_BASEREL_BIG));
	    r_jmptable= (0 != (rel->r_type[0] & RELOC_STD_BITS_JMPTABLE_BIG));
	    r_relative= (0 != (rel->r_type[0] & RELOC_STD_BITS_RELATIVE_BIG));
	    r_length  = ((rel->r_type[0] & RELOC_STD_BITS_LENGTH_BIG)
			 >> RELOC_STD_BITS_LENGTH_SH_BIG);
	  }
	else
	  {
	    r_index   = (((unsigned int) rel->r_index[2] << 16)
			 | ((unsigned int) rel->r_index[1] << 8)
			 | rel->r_index[0]);
	    r_extern  = (0 != (rel->r_type[0] & RELOC_STD_BITS_EXTERN_LITTLE));
	    r_pcrel   = (0 != (rel->r_type[0] & RELOC_STD_BITS_PCREL_LITTLE));
	    r_baserel = (0 != (rel->r_type[0]
			       & RELOC_STD_BITS_BASEREL_LITTLE));
	    r_jmptable= (0 != (rel->r_type[0]
			       & RELOC_STD_BITS_JMPTABLE_LITTLE));
	    r_relative= (0 != (rel->r_type[0]
			       & RELOC_STD_BITS_RELATIVE_LITTLE));
	    r_length  = ((rel->r_type[0] & RELOC_STD_BITS_LENGTH_LITTLE)
			 >> RELOC_STD_BITS_LENGTH_SH_LITTLE);
	  }

	howto_idx = (r_length + 4 * r_pcrel + 8 * r_baserel
		     + 16 * r_jmptable + 32 * r_relative);
	BFD_ASSERT (howto_idx < TABLE_SIZE (howto_table_std));
	howto = howto_table_std + howto_idx;
      }
#endif

      if (relocatable)
	{
	  /* We are generating a relocatable output file, and must
	     modify the reloc accordingly.  */
	  if (r_extern)
	    {
	      /* If we know the symbol this relocation is against,
		 convert it into a relocation against a section.  This
		 is what the native linker does.  */
	      h = sym_hashes[r_index];
	      if (h != NULL
		  && (h->root.type == bfd_link_hash_defined
		      || h->root.type == bfd_link_hash_defweak))
		{
		  asection *output_section;

		  /* Change the r_extern value.  */
		  if (bfd_header_big_endian (output_bfd))
		    rel->r_type[0] &= ~RELOC_STD_BITS_EXTERN_BIG;
		  else
		    rel->r_type[0] &= ~RELOC_STD_BITS_EXTERN_LITTLE;

		  /* Compute a new r_index.  */
		  output_section = h->root.u.def.section->output_section;
		  if (output_section == obj_textsec (output_bfd))
		    r_index = N_TEXT;
		  else if (output_section == obj_datasec (output_bfd))
		    r_index = N_DATA;
		  else if (output_section == obj_bsssec (output_bfd))
		    r_index = N_BSS;
		  else
		    r_index = N_ABS;

		  /* Add the symbol value and the section VMA to the
		     addend stored in the contents.  */
		  relocation = (h->root.u.def.value
				+ output_section->vma
				+ h->root.u.def.section->output_offset);
		}
	      else
		{
		  /* We must change r_index according to the symbol
		     map.  */
		  r_index = symbol_map[r_index];

		  if (r_index == -1)
		    {
		      if (h != NULL)
			{
			  /* We decided to strip this symbol, but it
			     turns out that we can't.  */
			  if (h->indx < 0)
			    {
			      h->indx = -2;
			      h->written = FALSE;
			      if (! MY (link_write_other_symbol) (h,
								  (void *) finfo))
				return FALSE;
			    }
			  r_index = h->indx;
			}
		      else
			{
			  const char *name;

			  name = strings + GET_WORD (input_bfd,
						     syms[r_index].e_strx);
			  if (! ((*finfo->info->callbacks->unattached_reloc)
				 (finfo->info, name, input_bfd, input_section,
				  r_addr)))
			    return FALSE;
			  r_index = 0;
			}
		    }

		  relocation = 0;
		}

	      /* Write out the new r_index value.  */
	      if (bfd_header_big_endian (output_bfd))
		{
		  rel->r_index[0] = r_index >> 16;
		  rel->r_index[1] = r_index >> 8;
		  rel->r_index[2] = r_index;
		}
	      else
		{
		  rel->r_index[2] = r_index >> 16;
		  rel->r_index[1] = r_index >> 8;
		  rel->r_index[0] = r_index;
		}
	    }
	  else
	    {
	      asection *section;

	      /* This is a relocation against a section.  We must
		 adjust by the amount that the section moved.  */
	      section = MY (reloc_index_to_section) (input_bfd, r_index);
	      relocation = (section->output_section->vma
			    + section->output_offset
			    - section->vma);
	    }

	  /* Change the address of the relocation.  */
	  PUT_WORD (output_bfd,
		    r_addr + input_section->output_offset,
		    rel->r_address);

	  /* Adjust a PC relative relocation by removing the reference
	     to the original address in the section and including the
	     reference to the new address.  */
	  if (r_pcrel)
	    relocation -= (input_section->output_section->vma
			   + input_section->output_offset
			   - input_section->vma);

#ifdef MY_relocatable_reloc
	  MY_relocatable_reloc (howto, output_bfd, rel, relocation, r_addr);
#endif

	  if (relocation == 0)
	    r = bfd_reloc_ok;
	  else
	    r = MY_relocate_contents (howto,
				      input_bfd, relocation,
				      contents + r_addr);
	}
      else
	{
	  bfd_boolean hundef;

	  /* We are generating an executable, and must do a full
	     relocation.  */
	  hundef = FALSE;

	  if (r_extern)
	    {
	      h = sym_hashes[r_index];

	      if (h != NULL
		  && (h->root.type == bfd_link_hash_defined
		      || h->root.type == bfd_link_hash_defweak))
		{
		  relocation = (h->root.u.def.value
				+ h->root.u.def.section->output_section->vma
				+ h->root.u.def.section->output_offset);
		}
	      else if (h != NULL
		       && h->root.type == bfd_link_hash_undefweak)
		relocation = 0;
	      else
		{
		  hundef = TRUE;
		  relocation = 0;
		}
	    }
	  else
	    {
	      asection *section;

	      section = MY (reloc_index_to_section) (input_bfd, r_index);


	      if (r_pcrel)
		relocation = (section->output_section->vma
			      + section->output_offset
			      - section->vma
			      + input_section->vma);
	      else
		relocation = (section->output_section->vma
			      + section->output_offset);

	    }

	  if (check_dynamic_reloc != NULL)
	    {
	      bfd_boolean skip;

	      if (! ((*check_dynamic_reloc)
		     (finfo->info, input_bfd, input_section, h,
		      (void *) rel, contents, &skip, &relocation)))
		return FALSE;
	      if (skip)
		continue;
	    }

	  /* Now warn if a global symbol is undefined.  */
	  if (hundef && ! finfo->info->shared && ! r_baserel)
	    {
	      const char *name;

	      if (h != NULL)
		name = h->root.root.string;
	      else
		name = strings + GET_WORD (input_bfd, syms[r_index].e_strx);
	      if (! ((*finfo->info->callbacks->undefined_symbol)
		     (finfo->info, name, input_bfd, input_section,
		      r_addr, TRUE)))
		return FALSE;
	    }

	  if (!r_extern)
	    {
	      asection *section = MY (reloc_index_to_section) (input_bfd, r_index);
	      unsigned long word = bfd_get_32 (input_bfd, contents + r_addr);

	    }

	  r = MY_final_link_relocate (howto,
				      input_bfd, input_section,
				      contents, r_addr, relocation,
				      (bfd_vma) 0);

	  if (!r_extern)
	    {
	      unsigned long word_after = bfd_get_32 (input_bfd, contents + r_addr);
	    }
	}

      if (r != bfd_reloc_ok)
	{
	  switch (r)
	    {
	    default:
	    case bfd_reloc_outofrange:
	      abort ();
	    case bfd_reloc_overflow:
	      {
		const char *name;

		if (h != NULL)
		  name = NULL;
		else if (r_extern)
		  name = strings + GET_WORD (input_bfd,
					     syms[r_index].e_strx);
		else
		  {
		    asection *s;

		    s = MY (reloc_index_to_section) (input_bfd, r_index);
		    name = bfd_section_name (input_bfd, s);
		  }
		if (! ((*finfo->info->callbacks->reloc_overflow)
		       (finfo->info, (h ? &h->root : NULL), name,
			howto->name, (bfd_vma) 0, input_bfd,
			input_section, r_addr)))
		  return FALSE;
	      }
	      break;
	    }
	}
    }

  return TRUE;
}

// From bfd/aoutx.h:4600
static bfd_boolean
MY (link_input_section) (struct MY (final_link_info) *finfo,
			 bfd *input_bfd,
			 asection *input_section,
			 file_ptr *reloff_ptr,
			 bfd_size_type rel_size)
{
  bfd_size_type input_size;
  void * relocs;

  /* Get the section contents.  */
  input_size = input_section->size;
  if (! bfd_get_section_contents (input_bfd, input_section,
				  (void *) finfo->contents,
				  (file_ptr) 0, input_size))
    return FALSE;

  /* Read in the relocs if we haven't already done it.  */
  if (aout_section_data (input_section) != NULL
      && aout_section_data (input_section)->relocs != NULL)
    relocs = aout_section_data (input_section)->relocs;
  else
    {
      relocs = finfo->relocs;
      if (rel_size > 0)
	{
	  if (bfd_seek (input_bfd, input_section->rel_filepos, SEEK_SET) != 0
	      || bfd_bread (relocs, rel_size, input_bfd) != rel_size)
	    return FALSE;
	}
    }

  /* Relocate the section contents.  */
  if (obj_reloc_entry_size (input_bfd) == RELOC_STD_SIZE)
    {
      if (! MY (link_input_section_std) (finfo, input_bfd, input_section,
					 (struct reloc_std_external *) relocs,
					 rel_size, finfo->contents))
	return FALSE;
    }
  else
    {
      if (! MY (link_input_section_ext) (finfo, input_bfd, input_section,
                                   (struct reloc_ext_external *) relocs,
                                   rel_size, finfo->contents))
	return FALSE;
    }

  /* Write out the section contents.  */
  if (! bfd_set_section_contents (finfo->output_bfd,
				  input_section->output_section,
				  (void *) finfo->contents,
				  (file_ptr) input_section->output_offset,
				  input_size))
    return FALSE;

  /* If we are producing relocatable output, the relocs were
     modified, and we now write them out.  */
  if (finfo->info->relocatable && rel_size > 0)
    {
      if (bfd_seek (finfo->output_bfd, *reloff_ptr, SEEK_SET) != 0)
	return FALSE;
      if (bfd_bwrite (relocs, rel_size, finfo->output_bfd) != rel_size)
	return FALSE;
      *reloff_ptr += rel_size;

      /* Assert that the relocs have not run into the symbols, and
	 that if these are the text relocs they have not run into the
	 data relocs.  */
      BFD_ASSERT (*reloff_ptr <= obj_sym_filepos (finfo->output_bfd)
		  && (reloff_ptr != &finfo->treloff
		      || (*reloff_ptr
			  <= obj_datasec (finfo->output_bfd)->rel_filepos)));
    }

  return TRUE;
}

// From bfd/aoutx.h:5164
static bfd_boolean
MY (link_input_bfd) (struct MY (final_link_info) *finfo, bfd *input_bfd)
{
  bfd_size_type sym_count;

  BFD_ASSERT (bfd_get_format (input_bfd) == bfd_object);

  /* If this is a dynamic object, it may need special handling.  */
  if ((input_bfd->flags & DYNAMIC) != 0
      && aout_backend_info (input_bfd)->link_dynamic_object != NULL)
    return ((*aout_backend_info (input_bfd)->link_dynamic_object)
	    (finfo->info, input_bfd));

  /* Get the symbols.  We probably have them already, unless
     finfo->info->keep_memory is FALSE.  */
  if (! MY (get_external_symbols) (input_bfd))
    return FALSE;

  sym_count = obj_aout_external_sym_count (input_bfd);

  /* Write out the symbols and get a map of the new indices.  The map
     is placed into finfo->symbol_map.  */
  if (! MY (link_write_symbols) (finfo, input_bfd))
    return FALSE;

  /* Relocate and write out the sections.  These functions use the
     symbol map created by aout_link_write_symbols.  The linker_mark
     field will be set if these sections are to be included in the
     link, which will normally be the case.  */
  if (obj_textsec (input_bfd)->linker_mark)
    {
      if (! MY (link_input_section) (finfo, input_bfd,
				     obj_textsec (input_bfd),
				     &finfo->treloff,
				     exec_hdr (input_bfd)->a_trsize))
	return FALSE;
    }
  if (obj_datasec (input_bfd)->linker_mark)
    {
      if (! MY (link_input_section) (finfo, input_bfd,
				     obj_datasec (input_bfd),
				     &finfo->dreloff,
				     exec_hdr (input_bfd)->a_drsize))
	return FALSE;
    }

  /* If we are not keeping memory, we don't need the symbols any
     longer.  We still need them if we are keeping memory, because the
     strings in the hash table point into them.  */
  if (! finfo->info->keep_memory)
    {
      if (! MY (link_free_symbols) (input_bfd))
	return FALSE;
    }

  return TRUE;
}

// From bfd/aoutx.h:5229
bfd_boolean
MY (final_link) (bfd *abfd,
		 struct bfd_link_info *info,
		 void (*callback) (bfd *, file_ptr *, file_ptr *, file_ptr *))
{
  struct MY (final_link_info) finfo;
  bfd_boolean includes_hash_initialized = FALSE;
  bfd *sub;
  bfd_size_type trsize, drsize;
  bfd_size_type max_contents_size;
  bfd_size_type max_relocs_size;
  bfd_size_type max_sym_count;
  bfd_size_type text_size;
  file_ptr text_end;
  struct bfd_link_order *p;
  asection *o;
  bfd_boolean have_link_order_relocs;

  if (info->shared)
    abfd->flags |= DYNAMIC;

  finfo.info = info;
  finfo.output_bfd = abfd;
  finfo.contents = NULL;
  finfo.relocs = NULL;
  finfo.symbol_map = NULL;
  finfo.output_syms = NULL;
  finfo.strtab = NULL;

  if (!bfd_hash_table_init_n (&finfo.includes.root,
			      MY (link_includes_newfunc),
			      sizeof (struct MY (link_includes_entry)),
			      251))
				  {
					goto error_return;
					}
  includes_hash_initialized = TRUE;

  /* Figure out the largest section size.  Also, if generating
     relocatable output, count the relocs.  */
  trsize = 0;
  drsize = 0;
  max_contents_size = 0;
  max_relocs_size = 0;
  max_sym_count = 0;
  for (sub = info->input_bfds; sub != NULL; sub = sub->link_next)
    {
      bfd_size_type sz;

      if (info->relocatable)
	{
	  if (bfd_get_flavour (sub) == bfd_target_aout_flavour)
	    {
	      trsize += exec_hdr (sub)->a_trsize;
	      drsize += exec_hdr (sub)->a_drsize;
	    }
	  else
	    {
	      /* FIXME: We need to identify the .text and .data sections
		 and call get_reloc_upper_bound and canonicalize_reloc to
		 work out the number of relocs needed, and then multiply
		 by the reloc size.  */
	      (*_bfd_error_handler)
		(_("%s: relocatable link from %s to %s not supported"),
		 bfd_get_filename (abfd),
		 sub->xvec->name, abfd->xvec->name);
	      bfd_set_error (bfd_error_invalid_operation);
	      goto error_return;
	    }
	}

      if (bfd_get_flavour (sub) == bfd_target_aout_flavour)
	{
	  sz = obj_textsec (sub)->size;
	  if (sz > max_contents_size)
	    max_contents_size = sz;
	  sz = obj_datasec (sub)->size;
	  if (sz > max_contents_size)
	    max_contents_size = sz;

	  sz = exec_hdr (sub)->a_trsize;
	  if (sz > max_relocs_size)
	    max_relocs_size = sz;
	  sz = exec_hdr (sub)->a_drsize;
	  if (sz > max_relocs_size)
	    max_relocs_size = sz;

	  sz = obj_aout_external_sym_count (sub);
	  if (sz > max_sym_count)
	    max_sym_count = sz;
	}
    }

  if (info->relocatable)
    {
      if (obj_textsec (abfd) != NULL)
	trsize += (_bfd_count_link_order_relocs (obj_textsec (abfd)
						 ->map_head.link_order)
		   * obj_reloc_entry_size (abfd));
      if (obj_datasec (abfd) != NULL)
	drsize += (_bfd_count_link_order_relocs (obj_datasec (abfd)
						 ->map_head.link_order)
		   * obj_reloc_entry_size (abfd));
    }

  exec_hdr (abfd)->a_trsize = trsize;
  exec_hdr (abfd)->a_drsize = drsize;


  exec_hdr (abfd)->a_entry = bfd_get_start_address (abfd);

  /* Adjust the section sizes and vmas according to the magic number.
     This sets a_text, a_data and a_bss in the exec_hdr and sets the
     filepos for each section.  */
  if (! NAME (aout, adjust_sizes_and_vmas) (abfd, &text_size, &text_end))
  {
    goto error_return;
}

  /* The relocation and symbol file positions differ among a.out
     targets.  We are passed a callback routine from the backend
     specific code to handle this.
     FIXME: At this point we do not know how much space the symbol
     table will require.  This will not work for any (nonstandard)
     a.out target that needs to know the symbol table size before it
     can compute the relocation file positions.  This may or may not
     be the case for the hp300hpux target, for example.  */
  (*callback) (abfd, &finfo.treloff, &finfo.dreloff,
	       &finfo.symoff);
  obj_textsec (abfd)->rel_filepos = finfo.treloff;
  obj_datasec (abfd)->rel_filepos = finfo.dreloff;
  obj_sym_filepos (abfd) = finfo.symoff;

  /* We keep a count of the symbols as we output them.  */
  obj_aout_external_sym_count (abfd) = 0;

  /* We accumulate the string table as we write out the symbols.  */
  finfo.strtab = _bfd_stringtab_init ();
  if (finfo.strtab == NULL)
    goto error_return;

  /* Allocate buffers to hold section contents and relocs.  */
  finfo.contents = bfd_malloc (max_contents_size);
  finfo.relocs = bfd_malloc (max_relocs_size);
  finfo.symbol_map = bfd_malloc (max_sym_count * sizeof (int));
  finfo.output_syms = bfd_malloc ((max_sym_count + 1)
				  * sizeof (struct external_nlist));
  if ((finfo.contents == NULL && max_contents_size != 0)
      || (finfo.relocs == NULL && max_relocs_size != 0)
      || (finfo.symbol_map == NULL && max_sym_count != 0)
      || finfo.output_syms == NULL)
    goto error_return;

  /* If we have a symbol named __DYNAMIC, force it out now.  This is
     required by SunOS.  Doing this here rather than in sunos.c is a
     hack, but it's easier than exporting everything which would be
     needed.  */
  {
    struct aout_link_hash_entry *h;


    h = aout_link_hash_lookup (aout_hash_table (info), "__DYNAMIC",
			       FALSE, FALSE, FALSE);
    if (h != NULL)
      MY (link_write_other_symbol) (h, &finfo);
  }

  /* The most time efficient way to do the link would be to read all
     the input object files into memory and then sort out the
     information into the output file.  Unfortunately, that will
     probably use too much memory.  Another method would be to step
     through everything that composes the text section and write it
     out, and then everything that composes the data section and write
     it out, and then write out the relocs, and then write out the
     symbols.  Unfortunately, that requires reading stuff from each
     input file several times, and we will not be able to keep all the
     input files open simultaneously, and reopening them will be slow.

     What we do is basically process one input file at a time.  We do
     everything we need to do with an input file once--copy over the
     section contents, handle the relocation information, and write
     out the symbols--and then we throw away the information we read
     from it.  This approach requires a lot of lseeks of the output
     file, which is unfortunate but still faster than reopening a lot
     of files.

     We use the output_has_begun field of the input BFDs to see
     whether we have already handled it.  */
  for (sub = info->input_bfds; sub != NULL; sub = sub->link_next)
    sub->output_has_begun = FALSE;

  /* Mark all sections which are to be included in the link.  This
     will normally be every section.  We need to do this so that we
     can identify any sections which the linker has decided to not
     include.  */
  for (o = abfd->sections; o != NULL; o = o->next)
    {
      for (p = o->map_head.link_order; p != NULL; p = p->next)
	if (p->type == bfd_indirect_link_order)
	  p->u.indirect.section->linker_mark = TRUE;
    }

  have_link_order_relocs = FALSE;
  for (o = abfd->sections; o != NULL; o = o->next)
    {
      for (p = o->map_head.link_order;
	   p != NULL;
	   p = p->next)
	{
	  if (p->type == bfd_indirect_link_order
	      && (bfd_get_flavour (p->u.indirect.section->owner)
		  == bfd_target_aout_flavour))
	    {
	      bfd *input_bfd;

	      input_bfd = p->u.indirect.section->owner;
	      if (! input_bfd->output_has_begun)
		{
		  if (! MY (link_input_bfd) (&finfo, input_bfd))
		    goto error_return;
		  input_bfd->output_has_begun = TRUE;
		}
	    }
	  else if (p->type == bfd_section_reloc_link_order
		   || p->type == bfd_symbol_reloc_link_order)
	    {
	      /* These are handled below.  */
	      have_link_order_relocs = TRUE;
	    }
	  else
	    {
	      if (! _bfd_default_link_order (abfd, info, o, p))
		goto error_return;
	    }
	}
    }

  /* Write out any symbols that we have not already written out.  */
  aout_link_hash_traverse (aout_hash_table (info),
			   MY (link_write_other_symbol),
			   (void *) &finfo);

  /* Now handle any relocs we were asked to create by the linker.
     These did not come from any input file.  We must do these after
     we have written out all the symbols, so that we know the symbol
     indices to use.  */
  if (have_link_order_relocs)
    {
      for (o = abfd->sections; o != NULL; o = o->next)
	{
	  for (p = o->map_head.link_order;
	       p != NULL;
	       p = p->next)
	    {
	      if (p->type == bfd_section_reloc_link_order
		  || p->type == bfd_symbol_reloc_link_order)
		{
		  if (! MY (link_reloc_link_order) (&finfo, o, p))
		    goto error_return;
		}
	    }
	}
    }

  if (finfo.contents != NULL)
    {
      free (finfo.contents);
      finfo.contents = NULL;
    }
  if (finfo.relocs != NULL)
    {
      free (finfo.relocs);
      finfo.relocs = NULL;
    }
  if (finfo.symbol_map != NULL)
    {
      free (finfo.symbol_map);
      finfo.symbol_map = NULL;
    }
  if (finfo.output_syms != NULL)
    {
      free (finfo.output_syms);
      finfo.output_syms = NULL;
    }
  if (includes_hash_initialized)
    {
      bfd_hash_table_free (&finfo.includes.root);
      includes_hash_initialized = FALSE;
    }

  /* Finish up any dynamic linking we may be doing.  */
  if (aout_backend_info (abfd)->finish_dynamic_link != NULL)
    {
      if (! (*aout_backend_info (abfd)->finish_dynamic_link) (abfd, info))
	goto error_return;
    }

  /* Update the header information.  */
  abfd->symcount = obj_aout_external_sym_count (abfd);
  exec_hdr (abfd)->a_syms = abfd->symcount * EXTERNAL_NLIST_SIZE;
  obj_str_filepos (abfd) = obj_sym_filepos (abfd) + exec_hdr (abfd)->a_syms;
  obj_textsec (abfd)->reloc_count =
    exec_hdr (abfd)->a_trsize / obj_reloc_entry_size (abfd);
  obj_datasec (abfd)->reloc_count =
    exec_hdr (abfd)->a_drsize / obj_reloc_entry_size (abfd);

  /* Write out the string table, unless there are no symbols.  */
  if (abfd->symcount > 0)
    {
      if (bfd_seek (abfd, obj_str_filepos (abfd), SEEK_SET) != 0
	  || ! MY (emit_stringtab) (abfd, finfo.strtab))
	goto error_return;
    }
  else if (obj_textsec (abfd)->reloc_count == 0
	   && obj_datasec (abfd)->reloc_count == 0)
    {
      bfd_byte b;
      file_ptr pos;

      b = 0;
      pos = obj_datasec (abfd)->filepos + exec_hdr (abfd)->a_data - 1;
      if (bfd_seek (abfd, pos, SEEK_SET) != 0
	  || bfd_bwrite (&b, (bfd_size_type) 1, abfd) != 1)
	goto error_return;
    }

  return TRUE;

 error_return:
  if (finfo.contents != NULL)
    free (finfo.contents);
  if (finfo.relocs != NULL)
    free (finfo.relocs);
  if (finfo.symbol_map != NULL)
    free (finfo.symbol_map);
  if (finfo.output_syms != NULL)
    free (finfo.output_syms);
  if (includes_hash_initialized)
    bfd_hash_table_free (&finfo.includes.root);
  return FALSE;
}