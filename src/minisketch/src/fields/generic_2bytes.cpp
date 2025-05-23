/**********************************************************************
 *   2018 Pieter Wuille, Greg Maxwell, Gleb Naumenko      *
 *       *
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

/* This file was substantially auto-generated by doc/gen_params.sage. */
#include "../fielddefines.h"

#if defined(ENABLE_FIELD_BYTES_INT_2)

#include "generic_common_impl.h"

#include "../lintrans.h"
#include "../sketch_impl.h"

#endif

#include "../sketch.h"

namespace {
#ifdef ENABLE_FIELD_INT_9
// 9 bit field
typedef RecLinTrans<uint16_t, 5, 4> StatTable9;
typedef RecLinTrans<uint16_t, 3, 3, 3> DynTable9;
constexpr StatTable9 SQR_TABLE_9({0x1, 0x4, 0x10, 0x40, 0x100, 0x6, 0x18, 0x60, 0x180});
constexpr StatTable9 QRT_TABLE_9({0, 0x4e, 0x4c, 0x1aa, 0x48, 0x22, 0x1a2, 0x100, 0x58});
typedef Field<uint16_t, 9, 3, StatTable9, DynTable9, &SQR_TABLE_9, &QRT_TABLE_9> Field9;
#endif

#ifdef ENABLE_FIELD_INT_10
// 10 bit field
typedef RecLinTrans<uint16_t, 5, 5> StatTable10;
typedef RecLinTrans<uint16_t, 4, 3, 3> DynTable10;
constexpr StatTable10 SQR_TABLE_10({0x1, 0x4, 0x10, 0x40, 0x100, 0x9, 0x24, 0x90, 0x240, 0x112});
constexpr StatTable10 QRT_TABLE_10({0xec, 0x86, 0x84, 0x30e, 0x80, 0x3c2, 0x306, 0, 0x90, 0x296});
typedef Field<uint16_t, 10, 9, StatTable10, DynTable10, &SQR_TABLE_10, &QRT_TABLE_10> Field10;
#endif

#ifdef ENABLE_FIELD_INT_11
// 11 bit field
typedef RecLinTrans<uint16_t, 6, 5> StatTable11;
typedef RecLinTrans<uint16_t, 4, 4, 3> DynTable11;
constexpr StatTable11 SQR_TABLE_11({0x1, 0x4, 0x10, 0x40, 0x100, 0x400, 0xa, 0x28, 0xa0, 0x280, 0x205});
constexpr StatTable11 QRT_TABLE_11({0x734, 0x48, 0x4a, 0x1de, 0x4e, 0x35e, 0x1d6, 0x200, 0x5e, 0, 0x37e});
typedef Field<uint16_t, 11, 5, StatTable11, DynTable11, &SQR_TABLE_11, &QRT_TABLE_11> Field11;
#endif

#ifdef ENABLE_FIELD_INT_12
// 12 bit field
typedef RecLinTrans<uint16_t, 6, 6> StatTable12;
typedef RecLinTrans<uint16_t, 4, 4, 4> DynTable12;
constexpr StatTable12 SQR_TABLE_12({0x1, 0x4, 0x10, 0x40, 0x100, 0x400, 0x9, 0x24, 0x90, 0x240, 0x900, 0x412});
constexpr StatTable12 QRT_TABLE_12({0x48, 0xc10, 0xc12, 0x208, 0xc16, 0xd82, 0x200, 0x110, 0xc06, 0, 0xda2, 0x5a4});
typedef Field<uint16_t, 12, 9, StatTable12, DynTable12, &SQR_TABLE_12, &QRT_TABLE_12> Field12;
#endif

#ifdef ENABLE_FIELD_INT_13
// 13 bit field
typedef RecLinTrans<uint16_t, 5, 4, 4> StatTable13;
typedef RecLinTrans<uint16_t, 4, 3, 3, 3> DynTable13;
constexpr StatTable13 SQR_TABLE_13({0x1, 0x4, 0x10, 0x40, 0x100, 0x400, 0x1000, 0x36, 0xd8, 0x360, 0xd80, 0x161b, 0x185a});
constexpr StatTable13 QRT_TABLE_13({0xcfc, 0x1500, 0x1502, 0x382, 0x1506, 0x149c, 0x38a, 0x118, 0x1516, 0, 0x14bc, 0x100e, 0x3ca});
typedef Field<uint16_t, 13, 27, StatTable13, DynTable13, &SQR_TABLE_13, &QRT_TABLE_13> Field13;
#endif

#ifdef ENABLE_FIELD_INT_14
// 14 bit field
typedef RecLinTrans<uint16_t, 5, 5, 4> StatTable14;
typedef RecLinTrans<uint16_t, 4, 4, 3, 3> DynTable14;
constexpr StatTable14 SQR_TABLE_14({0x1, 0x4, 0x10, 0x40, 0x100, 0x400, 0x1000, 0x21, 0x84, 0x210, 0x840, 0x2100, 0x442, 0x1108});
constexpr StatTable14 QRT_TABLE_14({0x13f2, 0x206, 0x204, 0x3e06, 0x200, 0x1266, 0x3e0e, 0x114, 0x210, 0, 0x1246, 0x2848, 0x3e4e, 0x2258});
typedef Field<uint16_t, 14, 33, StatTable14, DynTable14, &SQR_TABLE_14, &QRT_TABLE_14> Field14;
#endif

#ifdef ENABLE_FIELD_INT_15
// 15 bit field
typedef RecLinTrans<uint16_t, 5, 5, 5> StatTable15;
typedef RecLinTrans<uint16_t, 4, 4, 4, 3> DynTable15;
constexpr StatTable15 SQR_TABLE_15({0x1, 0x4, 0x10, 0x40, 0x100, 0x400, 0x1000, 0x4000, 0x6, 0x18, 0x60, 0x180, 0x600, 0x1800, 0x6000});
constexpr StatTable15 QRT_TABLE_15({0, 0x114, 0x116, 0x428, 0x112, 0x137a, 0x420, 0x6d62, 0x102, 0x73a, 0x135a, 0x6460, 0x460, 0x4000, 0x6de2});
typedef Field<uint16_t, 15, 3, StatTable15, DynTable15, &SQR_TABLE_15, &QRT_TABLE_15> Field15;
#endif

#ifdef ENABLE_FIELD_INT_16
// 16 bit field
typedef RecLinTrans<uint16_t, 6, 5, 5> StatTable16;
typedef RecLinTrans<uint16_t, 4, 4, 4, 4> DynTable16;
constexpr StatTable16 SQR_TABLE_16({0x1, 0x4, 0x10, 0x40, 0x100, 0x400, 0x1000, 0x4000, 0x2b, 0xac, 0x2b0, 0xac0, 0x2b00, 0xac00, 0xb056, 0xc10e});
constexpr StatTable16 QRT_TABLE_16({0x732, 0x72b8, 0x72ba, 0x7e96, 0x72be, 0x78b2, 0x7e9e, 0x8cba, 0x72ae, 0xfa24, 0x7892, 0x5892, 0x7ede, 0xbec6, 0x8c3a, 0});
typedef Field<uint16_t, 16, 43, StatTable16, DynTable16, &SQR_TABLE_16, &QRT_TABLE_16> Field16;
#endif
}

Sketch* ConstructGeneric2Bytes(int bits, int implementation)
{
    switch (bits) {
#ifdef ENABLE_FIELD_INT_9
    case 9: return new SketchImpl<Field9>(implementation, 9);
#endif
#ifdef ENABLE_FIELD_INT_10
    case 10: return new SketchImpl<Field10>(implementation, 10);
#endif
#ifdef ENABLE_FIELD_INT_11
    case 11: return new SketchImpl<Field11>(implementation, 11);
#endif
#ifdef ENABLE_FIELD_INT_12
    case 12: return new SketchImpl<Field12>(implementation, 12);
#endif
#ifdef ENABLE_FIELD_INT_13
    case 13: return new SketchImpl<Field13>(implementation, 13);
#endif
#ifdef ENABLE_FIELD_INT_14
    case 14: return new SketchImpl<Field14>(implementation, 14);
#endif
#ifdef ENABLE_FIELD_INT_15
    case 15: return new SketchImpl<Field15>(implementation, 15);
#endif
#ifdef ENABLE_FIELD_INT_16
    case 16: return new SketchImpl<Field16>(implementation, 16);
#endif
    default: return nullptr;
    }
}
