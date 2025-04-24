//   2015-2022 
//    
//  

#ifndef BITCOIN_COMMON_URL_H
#define BITCOIN_COMMON_URL_H

#include <string>
#include <string_view>

/* Decode a URL.
 *
 * Notably this implementation does not decode a '+' to a ' '.
 */
std::string UrlDecode(std::string_view url_encoded);

#endif // BITCOIN_COMMON_URL_H
