/* obj-plan9.h, Plan 9 object file format for gas, the assembler.
   Copyright (C) 1989, 90, 91, 92, 93, 94, 95, 96, 98, 99, 2000
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

#define obj_frob_file obj_plan9_frob_file
#define obj_frob_file_after_relocs obj_plan9_frob_file_after_relocs
#define obj_frob_symbol obj_plan9_frob_symbol


/* Tag to validate Plan 9 object file format processing */
#define OBJ_PLAN9 1

#include "targ-cpu.h"

#include "bfd/libaout.h"

void obj_plan9_frob_file (void);
void obj_plan9_frob_file_after_relocs (void);
void obj_plan9_frob_symbol (symbolS *symp, int *puntp);

/* binutils 2.17 does not have bfd_target_plan9_flavour; use a.out flavour.  3DEL*/
//#ifndef OUTPUT_FLAVOR
//#define OUTPUT_FLAVOR bfd_target_aout_flavour
//#endif

extern const pseudo_typeS aout_pseudo_table[];

#ifndef obj_pop_insert
#define obj_pop_insert() pop_insert (aout_pseudo_table)
#endif

/* SYMBOL TABLE */
/* Symbol table entry data type */
typedef struct nlist obj_symbol_type;	/* Symbol table entry */

/* Symbol table macros and constants */

/* These accessors are format-specific and are used in places where
   the generic symbols.h API does not provide a function variant.  */
#define S_SET_OTHER(S,V) \
  (aout_symbol (symbol_get_bfdsym (S))->other = (V))
#define S_SET_TYPE(S,T) \
  (aout_symbol (symbol_get_bfdsym (S))->type = (T))
#define S_SET_DESC(S,D)	\
  (aout_symbol (symbol_get_bfdsym (S))->desc = (D))

#define S_GET_OTHER(S) \
  (aout_symbol (symbol_get_bfdsym (S))->other)
#define S_GET_TYPE(S) \
  (aout_symbol (symbol_get_bfdsym (S))->type)
#define S_GET_DESC(S) \
  (aout_symbol (symbol_get_bfdsym (S))->desc)

/* These are provided by GAS; some backends declare them here.  Keep as in-tree
   convention with other a.out-ish formats.  */
//2DEL
//asection *text_section, *data_section, *bss_section;
extern asection *text_section, *data_section, *bss_section;

#define obj_sec_sym_ok_for_reloc(SEC)	(1)

#define obj_read_begin_hook()	{;}
#define obj_symbol_new_hook(s)	{;}

#define EMIT_SECTION_SYMBOLS		0

#define AOUT_STABS
