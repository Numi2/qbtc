//   2022 
//    
//  

#include <node/coins_view_args.h>

#include <common/args.h>
#include <txdb.h>

namespace node {
void ReadCoinsViewArgs(const ArgsManager& args, CoinsViewOptions& options)
{
    if (auto value = args.GetIntArg("-dbbatchsize")) options.batch_write_bytes = *value;
    if (auto value = args.GetIntArg("-dbcrashratio")) options.simulate_crash_ratio = *value;
}
} // namespace node
