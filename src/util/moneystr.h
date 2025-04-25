 
// src/util/moneystr.h

/**
 * Money parsing/formatting utilities.
 */
#ifndef QUBITCOIN_UTIL_MONEYSTR_H
#define QUBITCOIN_UTIL_MONEYSTR_H

#include <consensus/amount.h>

#include <optional>
#include <string>

/* Do not use these functions to represent or parse monetary amounts to or from
 * JSON but use AmountFromValue and ValueFromAmount for that.
 */
std::string FormatMoney(const CAmount n);
/** Parse an amount denoted in full coins. E.g. "0.0034" supplied on the command line. **/
std::optional<CAmount> ParseMoney(const std::string& str);

#endif // QUBITCOIN_UTIL_MONEYSTR_H
