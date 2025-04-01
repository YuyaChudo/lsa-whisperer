//// Copyright (C) 2024 Evan McBroom
////
//// Local security authority (lsa)
////
//// This header is a work in progress.
////
#pragma once
#include "ksecdd.h"
#include "spm.h"

typedef struct _LSA_TOKEN_INFO_HEADER {
    unsigned long cbTotal;
    unsigned long TokenInfoType;
} LSA_TOKEN_INFO_HEADER, *PLSA_TOKEN_INFO_HEADER;