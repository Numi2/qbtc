//   2018 
//    
//  

#ifndef BITCOIN_COMPAT_STDIN_H
#define BITCOIN_COMPAT_STDIN_H

struct NoechoInst {
    NoechoInst();
    ~NoechoInst();
};

#define NO_STDIN_ECHO() NoechoInst _no_echo

bool StdinTerminal();
bool StdinReady();

#endif // BITCOIN_COMPAT_STDIN_H
