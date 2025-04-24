//  
//    
//  

#ifndef BITCOIN_UTIL_BATCHPRIORITY_H
#define BITCOIN_UTIL_BATCHPRIORITY_H

/**
 * On platforms that support it, tell the kernel the calling thread is
 * CPU-intensive and non-interactive. See SCHED_BATCH in sched(7) for details.
 *
 */
void ScheduleBatchPriority();

#endif // BITCOIN_UTIL_BATCHPRIORITY_H
