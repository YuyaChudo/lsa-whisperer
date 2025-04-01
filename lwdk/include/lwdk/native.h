// Copyright (C) 2024 Evan McBroom
//
// Native types
//
// This is a minimal set of native types which are required
// by other lwdk headers and are not otherwise defined in the
// Windows SDK, WDK, or the Process Hacker NT library.
//
#pragma once
// clang-format off
#include <phnt_windows.h>
#include <phnt.h>
// clang-format on

typedef struct _RTL_AVL_TREE {
    PRTL_BALANCED_NODE Root;
} RTL_AVL_TREE, *PRTL_AVL_TREE, MM_AVL_TABLE, *PMM_AVL_TABLE;