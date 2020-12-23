//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    def.h
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _TLSSCAN_DEF_H
#define _TLSSCAN_DEF_H
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef STATUS_OK
#define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
#define STATUS_ERROR -1
#endif
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
// array size calc
#ifndef ARRAY_SIZE
# define ARRAY_SIZE(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif
// element at
#ifndef ELEM_AT
# define ELEM_AT(_a, _i, _v) ((unsigned int)(_i) < ARRAY_SIZE(_a) ? (_a)[(_i)] : (_v))
#endif
#endif
