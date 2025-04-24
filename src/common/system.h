// 
//   2009-present 
//    
//  

#ifndef BITCOIN_COMMON_SYSTEM_H
#define BITCOIN_COMMON_SYSTEM_H

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <cstdint>
#include <string>

// Application startup time (used for uptime calculation)
int64_t GetStartupTime();

void SetupEnvironment();
[[nodiscard]] bool SetupNetworking();
#ifndef WIN32
std::string ShellEscape(const std::string& arg);
#endif
#if HAVE_SYSTEM
void runCommand(const std::string& strCommand);
#endif

/**
 * Return the number of cores available on the current system.
 * @note This does count virtual cores, such as those provided by HyperThreading.
 */
int GetNumCores();

#endif // BITCOIN_COMMON_SYSTEM_H
