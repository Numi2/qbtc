// 
//     23 
//    
//  

#ifndef BITCOIN_UTIL_EXCEPTION_H
#define BITCOIN_UTIL_EXCEPTION_H

#include <exception>
#include <string_view>

void PrintExceptionContinue(const std::exception* pex, std::string_view thread_name);

#endif // BITCOIN_UTIL_EXCEPTION_H
