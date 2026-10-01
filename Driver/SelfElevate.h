#pragma once

//
// Client-side token elevation.
//
// Unlike TaskImpersonate.c - which borrows the System token for the duration
// of one file operation and hands it straight back - the calls here leave the
// token attached to the calling thread. That difference is the whole feature.
// Read the scope note at the top of SelfElevate.c before using them.
//

#include "TaskCompat.h"

NTSTATUS SelfElevate(VOID);
NTSTATUS SelfUnelevate(VOID);
NTSTATUS SelfQueryElevation(PULONG Elevated);
