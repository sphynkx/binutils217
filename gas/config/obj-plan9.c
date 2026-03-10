/* Plan 9 object file format.
	- Like a.out format, but always use big endian for headers, symbols etc.

   Copyright (C) 1989, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 2000
   Free Software Foundation, Inc.

This file is part of GAS, the GNU Assembler.

GAS is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2,
or (at your option) any later version.

GAS is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GAS; see the file COPYING.  If not, write to the Free
Software Foundation, 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#define OBJ_HEADER "obj-plan9.h"

#include "as.h"
#include "subsegs.h"
#include "safe-ctype.h"


#undef NO_RELOC
#include "aout/aout64.h"

#include "obstack.h"

static void obj_plan9_line PARAMS ((int));
static void obj_plan9_weak PARAMS ((int));
static void obj_plan9_type PARAMS ((int));
static void obj_plan9_section (int);


/* start of patch1 for fix relocs */
/* Plan 9 a.out: ensure REL addends for section-based relocations are
   stored in-place.  GAS fixup processing may collapse local symbol relocs
   to section symbols and move the symbol value into fx_offset.  For a.out
   "std" relocs the addend lives in the relocated word, so we must write
   fx_offset into the field.  */

static void
obj_plan9_patch_inplace_addends (void)
{
  asection *sec;

  for (sec = stdoutput->sections; sec != NULL; sec = sec->next)
    {
      segment_info_type *seginfo = seg_info (sec);
      fixS *fixp;

      if (seginfo == NULL)
        continue;

      for (fixp = seginfo->fix_root; fixp != NULL; fixp = fixp->fx_next)
        {
          symbolS *sym;
          segT sseg;
          char *p;
          valueT v;

          if (fixp->fx_done)
            continue;

          /* Only handle absolute 32-bit (your failing case).
             Extend later if needed. */
          if (fixp->fx_pcrel)
            continue;

          if (fixp->fx_size != 4)
            continue;

          sym = fixp->fx_addsy;
          if (sym == NULL)
            continue;

          /* We only care about the case where write.c collapsed a local
             symbol reloc into a section symbol. */
          if (!symbol_section_p (sym))
            continue;

          sseg = S_GET_SEGMENT (sym);
          if (sseg != text_section && sseg != data_section && sseg != bss_section)
            continue;

          /* Write fx_offset into the relocated field. */
          p = fixp->fx_frag->fr_literal + fixp->fx_where;
          v = fixp->fx_offset;

          /* Plan 9 i386 is little-endian. */
          p[0] = (v      ) & 0xff;
          p[1] = (v >>  8) & 0xff;
          p[2] = (v >> 16) & 0xff;
          p[3] = (v >> 24) & 0xff;

          fprintf (stderr,
                   "DBG plan9: inplace-addend sec=%s where=%ld size=%d symsec=%s fx_offset=%ld\n",
                   sec->name,
                   (long) fixp->fx_where,
                   fixp->fx_size,
                   sseg == text_section ? ".text" : (sseg == data_section ? ".data" : ".bss"),
                   (long) fixp->fx_offset);
        }
    }
}

/// replaced temp. with debug-version
//static void
//obj_plan9_frob_file_after_relocs (void)
//{
//	fprintf(stderr, "DBG plan9: frob_file_after_relocs called\n");
//  /* Only meaningful for a.out flavour.  */
//  if (OUTPUT_FLAVOR == bfd_target_aout_flavour)
//    obj_plan9_patch_inplace_addends ();
//}
///////////////static 
void
obj_plan9_frob_file_after_relocs (void)
{
  asection *sec;

	fprintf (stderr, "DBG plan9: frob_file_after_relocs called (OUTPUT_FLAVOR=%d)\n",
           (int) OUTPUT_FLAVOR);

  for (sec = stdoutput->sections; sec != NULL; sec = sec->next)
    {
      segment_info_type *seginfo = seg_info (sec);
      fixS *fixp;
      int k = 0;

      if (seginfo == NULL)
        continue;

      for (fixp = seginfo->fix_root; fixp != NULL; fixp = fixp->fx_next)
        {
          symbolS *sym = fixp->fx_addsy;
          const char *symname = sym ? S_GET_NAME (sym) : "(null)";
          const char *symseg = "(noseg)";

		/* If relocation is against a section symbol, ensure the in-place addend
		   contains the section VMA, to match a.out "symbols from 0" semantics. */
		if (!fixp->fx_done
			&& !fixp->fx_pcrel
			&& fixp->fx_size == 4
			&& fixp->fx_addsy != NULL
			&& symbol_section_p (fixp->fx_addsy))
		  {
			segT sseg = S_GET_SEGMENT (fixp->fx_addsy);
			valueT v = 0;
			char *p = fixp->fx_frag->fr_literal + fixp->fx_where;

			if (sseg == text_section)
			  v = text_section->vma;
			else if (sseg == data_section)
			  v = data_section->vma;
			else if (sseg == bss_section)
			  v = bss_section->vma;
			else
			  v = 0;

			/* Write little-endian 32-bit. */
			p[0] = (v      ) & 0xff;
			p[1] = (v >>  8) & 0xff;
			p[2] = (v >> 16) & 0xff;
			p[3] = (v >> 24) & 0xff;

			fprintf (stderr,
					 "DBG plan9: patched in-place addend to %#lx for %s at where=%ld\n",
					 (unsigned long) v,
					 (sseg == text_section ? ".text" : (sseg == data_section ? ".data" : ".bss")),
					 (long) fixp->fx_where);
		  }

          if (sym)
            {
              segT sseg = S_GET_SEGMENT (sym);
              if (sseg == text_section) symseg = ".text";
              else if (sseg == data_section) symseg = ".data";
              else if (sseg == bss_section) symseg = ".bss";
              else if (sseg == absolute_section) symseg = "ABS";
              else if (sseg == undefined_section) symseg = "UND";
            }

          if (k < 20)
            fprintf (stderr,
                     "DBG plan9: fix sec=%s where=%ld size=%d pcrel=%d done=%d off=%ld addn=%ld sym=%s symseg=%s sectsym=%d\n",
                     sec->name,
                     (long) fixp->fx_where,
                     fixp->fx_size,
                     fixp->fx_pcrel,
                     fixp->fx_done,
                     (long) fixp->fx_offset,
                     (long) fixp->fx_addnumber,
                     symname,
                     symseg,
                     (sym && symbol_section_p (sym)) ? 1 : 0);
          k++;
        }
    }
}

/* end of patch1 for fix relocs */



const pseudo_typeS aout_pseudo_table[] =
{
	/* fix old-ported gas.. at first for test.. */
	{"section", obj_plan9_section, 0},
	{"p2align", s_align_ptwo, 0},

  {"line", obj_plan9_line, 0},	/* source code line number */
  {"ln", obj_plan9_line, 0},	/* coff line number that we use anyway */

  {"weak", obj_plan9_weak, 0},	/* mark symbol as weak.  */

  {"type", obj_plan9_type, 0},

  /* coff debug pseudos (ignored) */
  {"def", s_ignore, 0},
  {"dim", s_ignore, 0},
  {"endef", s_ignore, 0},
  {"ident", s_ignore, 0},
  {"line", s_ignore, 0},
  {"ln", s_ignore, 0},
  {"scl", s_ignore, 0},
  {"size", s_ignore, 0},
  {"tag", s_ignore, 0},
  {"val", s_ignore, 0},
  {"version", s_ignore, 0},

  {"optim", s_ignore, 0},	/* For sun386i cc (?) */

  /* other stuff */
  {"ABORT", s_abort, 0},

  {NULL, NULL, 0}		/* end sentinel */
};				/* aout_pseudo_table */



/* Minimal .section handler for Plan 9 a.out backend.
   We map most gcc/elf section names into {.text,.data,.bss}.  */

static void
obj_plan9_section (int ignore)
{
  char *name;
  segT sec;

  (void) ignore;

  while (ISSPACE (*input_line_pointer))
    input_line_pointer++;

  if (*input_line_pointer == '"')
    {
      int len;
      name = demand_copy_C_string (&len);
      /* name now points to newly allocated NUL-terminated string. */
      if (strncmp (name, ".text", 5) == 0)
        sec = subseg_new (".text", 0);
      else if (strncmp (name, ".data", 5) == 0
            || strncmp (name, ".rodata", 7) == 0)
        sec = subseg_new (".data", 0);
      else if (strncmp (name, ".bss", 4) == 0)
        sec = subseg_new (".bss", 0);
      else
        sec = subseg_new (".text", 0);

      subseg_set (sec, 0);
      free (name);

      ignore_rest_of_line ();
      return;
    }
  else
    {
      char *start = input_line_pointer;
      char *p = start;
      char save;

      while (*p && *p != ',' && !ISSPACE (*p))
        p++;

      save = *p;
      *p = 0;
      name = start;

      if (strncmp (name, ".text", 5) == 0)
        sec = subseg_new (".text", 0);
      else if (strncmp (name, ".data", 5) == 0
            || strncmp (name, ".rodata", 7) == 0)
        sec = subseg_new (".data", 0);
      else if (strncmp (name, ".bss", 4) == 0)
        sec = subseg_new (".bss", 0);
      else
        sec = subseg_new (".text", 0);

      *p = save;
      input_line_pointer = p;

      subseg_set (sec, 0);
      ignore_rest_of_line ();
      return;
    }
}



void
obj_plan9_frob_symbol (sym, punt)
     symbolS *sym;
     int *punt ATTRIBUTE_UNUSED;
{
  flagword flags;
  asection *sec;
  int desc, type, other;

  flags = symbol_get_bfdsym (sym)->flags;
  desc = aout_symbol (symbol_get_bfdsym (sym))->desc;
  type = aout_symbol (symbol_get_bfdsym (sym))->type;
  other = aout_symbol (symbol_get_bfdsym (sym))->other;
  sec = S_GET_SEGMENT (sym);

  /* Only frob simple symbols this way right now.  */
  if (! (type & ~ (N_TYPE | N_EXT)))
    {
      if (type == (N_UNDF | N_EXT)
	  && sec == &bfd_abs_section)
	{
	  sec = bfd_und_section_ptr;
	  S_SET_SEGMENT (sym, sec);
	}

      if ((type & N_TYPE) != N_INDR
	  && (type & N_TYPE) != N_SETA
	  && (type & N_TYPE) != N_SETT
	  && (type & N_TYPE) != N_SETD
	  && (type & N_TYPE) != N_SETB
	  && type != N_WARNING
	  && (sec == &bfd_abs_section
	      || sec == &bfd_und_section))
	return;
      if (flags & BSF_EXPORT)
	type |= N_EXT;

      switch (type & N_TYPE)
	{
	case N_SETA:
	case N_SETT:
	case N_SETD:
	case N_SETB:
	  /* Set the debugging flag for constructor symbols so that
	     BFD leaves them alone.  */
	  symbol_get_bfdsym (sym)->flags |= BSF_DEBUGGING;

	  /* You can't put a common symbol in a set.  The way a set
	     element works is that the symbol has a definition and a
	     name, and the linker adds the definition to the set of
	     that name.  That does not work for a common symbol,
	     because the linker can't tell which common symbol the
	     user means.  FIXME: Using as_bad here may be
	     inappropriate, since the user may want to force a
	     particular type without regard to the semantics of sets;
	     on the other hand, we certainly don't want anybody to be
	     mislead into thinking that their code will work.  */
	  if (S_IS_COMMON (sym))
	    as_bad (_("Attempt to put a common symbol into set %s"),
		    S_GET_NAME (sym));
	  /* Similarly, you can't put an undefined symbol in a set.  */
	  else if (! S_IS_DEFINED (sym))
	    as_bad (_("Attempt to put an undefined symbol into set %s"),
		    S_GET_NAME (sym));

	  break;
	case N_INDR:
	  /* Put indirect symbols in the indirect section.  */
	  S_SET_SEGMENT (sym, bfd_ind_section_ptr);
	  symbol_get_bfdsym (sym)->flags |= BSF_INDIRECT;
	  if (type & N_EXT)
	    {
	      symbol_get_bfdsym (sym)->flags |= BSF_EXPORT;
	      symbol_get_bfdsym (sym)->flags &=~ BSF_LOCAL;
	    }
	  break;
	case N_WARNING:
	  /* Mark warning symbols.  */
	  symbol_get_bfdsym (sym)->flags |= BSF_WARNING;
	  break;
	}
    }
  else
    {
      symbol_get_bfdsym (sym)->flags |= BSF_DEBUGGING;
    }

  aout_symbol (symbol_get_bfdsym (sym))->type = type;

  /* Double check weak symbols.  */
  if (S_IS_WEAK (sym))
    {
      if (S_IS_COMMON (sym))
	as_bad (_("Symbol `%s' can not be both weak and common"),
		S_GET_NAME (sym));
    }
}

void
obj_plan9_frob_file ()
{
  /* Relocation processing may require knowing the VMAs of the sections.
     Since writing to a section will cause the BFD back end to compute the
     VMAs, fake it out here....  */
	fprintf(stderr, "DBG plan9: obj_plan9_frob_file called\n");
  bfd_byte b = 0;
  bfd_boolean x = TRUE;

  if (bfd_section_size (stdoutput, text_section) != 0)
    {
      x = bfd_set_section_contents (stdoutput, text_section, &b, (file_ptr) 0,
				    (bfd_size_type) 1);
    }
  else if (bfd_section_size (stdoutput, data_section) != 0)
    {
      x = bfd_set_section_contents (stdoutput, data_section, &b, (file_ptr) 0,
				    (bfd_size_type) 1);
    }
  assert (x == TRUE);
}

static void
obj_plan9_line (ignore)
     int ignore ATTRIBUTE_UNUSED;
{
  /* Assume delimiter is part of expression.
     BSD4.2 as fails with delightful bug, so we
     are not being incompatible here.  */
  new_logical_line ((char *) NULL, (int) (get_absolute_expression ()));
  demand_empty_rest_of_line ();
}				/* obj_plan9_line() */

/* Handle .weak.  This is a GNU extension.  */

static void
obj_plan9_weak (ignore)
     int ignore ATTRIBUTE_UNUSED;
{
  char *name;
  int c;
  symbolS *symbolP;

  do
    {
      name = input_line_pointer;
      c = get_symbol_end ();
      symbolP = symbol_find_or_make (name);
      *input_line_pointer = c;
      SKIP_WHITESPACE ();
      S_SET_WEAK (symbolP);
      if (c == ',')
	{
	  input_line_pointer++;
	  SKIP_WHITESPACE ();
	  if (*input_line_pointer == '\n')
	    c = '\n';
	}
    }
  while (c == ',');
  demand_empty_rest_of_line ();
}

/* Handle .type.  On {Net,Open}BSD, this is used to set the n_other field,
   which is then apparently used when doing dynamic linking.  Older
   versions of gas ignored the .type pseudo-op, so we also ignore it if
   we can't parse it.  */

static void
obj_plan9_type (ignore)
     int ignore ATTRIBUTE_UNUSED;
{
  char *name;
  int c;
  symbolS *sym;

  name = input_line_pointer;
  c = get_symbol_end ();
  sym = symbol_find_or_make (name);
  *input_line_pointer = c;
  SKIP_WHITESPACE ();
  if (*input_line_pointer == ',')
    {
      ++input_line_pointer;
      SKIP_WHITESPACE ();
      if (*input_line_pointer == '@')
	{
	  ++input_line_pointer;
	  if (strncmp (input_line_pointer, "object", 6) == 0)
	    aout_symbol (symbol_get_bfdsym (sym))->other = 1;
	  else if (strncmp (input_line_pointer, "function", 8) == 0)
	    aout_symbol (symbol_get_bfdsym (sym))->other = 2;
	}
    }

  /* Ignore everything else on the line.  */
  s_ignore (0);
}

/* Support for an AOUT emulation.  */

static void plan9_pop_insert PARAMS ((void));
static int obj_plan9_s_get_other PARAMS ((symbolS *));
static void obj_plan9_s_set_other PARAMS ((symbolS *, int));
static int obj_plan9_s_get_desc PARAMS ((symbolS *));
static void obj_plan9_s_set_desc PARAMS ((symbolS *, int));
static int obj_plan9_s_get_type PARAMS ((symbolS *));
static void obj_plan9_s_set_type PARAMS ((symbolS *, int));
static int obj_plan9_separate_stab_sections PARAMS ((void));
static int obj_plan9_sec_sym_ok_for_reloc PARAMS ((asection *));
static void obj_plan9_process_stab PARAMS ((segT, int, const char *, int, int, int));

static void
plan9_pop_insert ()
{
  pop_insert (aout_pseudo_table);
}

static int
obj_plan9_s_get_other (sym)
     symbolS *sym;
{
  return aout_symbol (symbol_get_bfdsym (sym))->other;
}

static void
obj_plan9_s_set_other (sym, o)
     symbolS *sym;
     int o;
{
  aout_symbol (symbol_get_bfdsym (sym))->other = o;
}

static int
obj_plan9_sec_sym_ok_for_reloc (sec)
     asection *sec ATTRIBUTE_UNUSED;
{
  return obj_sec_sym_ok_for_reloc (sec);
}

static void
obj_plan9_process_stab (seg, w, s, t, o, d)
     segT seg ATTRIBUTE_UNUSED;
     int w;
     const char *s;
     int t;
     int o;
     int d;
{
  aout_process_stab (w, s, t, o, d);
}

static int
obj_plan9_s_get_desc (sym)
     symbolS *sym;
{
  return aout_symbol (symbol_get_bfdsym (sym))->desc;
}

static void
obj_plan9_s_set_desc (sym, d)
     symbolS *sym;
     int d;
{
  aout_symbol (symbol_get_bfdsym (sym))->desc = d;
}

static int
obj_plan9_s_get_type (sym)
     symbolS *sym;
{
  return aout_symbol (symbol_get_bfdsym (sym))->type;
}

static void
obj_plan9_s_set_type (sym, t)
     symbolS *sym;
     int t;
{
  aout_symbol (symbol_get_bfdsym (sym))->type = t;
}

static int
obj_plan9_separate_stab_sections ()
{
  return 0;
}

/* When changed, make sure these table entries match the single-format
   definitions in obj-plan9.h.  */
const struct format_ops plan9_format_ops =
{
  bfd_target_aout_flavour,
  1,	/* dfl_leading_underscore */
  0,	/* emit_section_symbols */
  0,	/* begin */
  0,	/* app_file */
  obj_plan9_frob_symbol,
  obj_plan9_frob_file,
  0,	/* frob_file_before_adjust */
  obj_plan9_frob_file_after_relocs, /* patch2 insert hook Was:  0,	/ * frob_file_after_relocs * / */
  0,	/* s_get_size */
  0,	/* s_set_size */
  0,	/* s_get_align */
  0,	/* s_set_align */
  obj_plan9_s_get_other,
  obj_plan9_s_set_other,
  obj_plan9_s_get_desc,
  obj_plan9_s_set_desc,
  obj_plan9_s_get_type,
  obj_plan9_s_set_type,
  0,	/* copy_symbol_attributes */
  0,	/* generate_asm_lineno */
  obj_plan9_process_stab,
  obj_plan9_separate_stab_sections,
  0,	/* init_stab_section */
  obj_plan9_sec_sym_ok_for_reloc,
  plan9_pop_insert,
  0,	/* ecoff_set_ext */
  0,	/* read_begin_hook */
  0 	/* symbol_new_hook */
};