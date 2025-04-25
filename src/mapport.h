// src/mapport.h

#ifndef QUBITCOIN_MAPPORT_H
#define QUBITCOIN_MAPPORT_H

static constexpr bool DEFAULT_NATPMP = false;

void StartMapPort(bool enable);
void InterruptMapPort();
void StopMapPort();

#endif // QUBITCOIN_MAPPORT_H
