// src/util/macros.h

#ifndef QUBITCOIN_UTIL_MACROS_H
#define QUBITCOIN_UTIL_MACROS_H

#define PASTE(x, y) x ## y
#define PASTE2(x, y) PASTE(x, y)

#define UNIQUE_NAME(name) PASTE2(name, __COUNTER__)

/**
 * Converts the parameter X to a string after macro replacement on X has been performed.
 * Don't merge these into one macro!
 */
#define STRINGIZE(X) DO_STRINGIZE(X)
#define DO_STRINGIZE(X) #X

#endif // QUBITCOIN_UTIL_MACROS_H
