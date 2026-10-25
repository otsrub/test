// Recovered Logic 0x123dbc..0x123df0. Shared ABI footprint; whole-class integration pending.
using U=unsigned; using Q=unsigned long long;
class ScRastral { public: static float s_followStaffFloat[16]; };
float ScRastral::s_followStaffFloat[16];
extern "C" { unsigned char ml_logic_global_guard[1024]; }
extern "C" Q ml_logic_follow_staff_init(Q x0) {
 const U bits[16]={0x3eae4c41,0x3ec415ca,0x3edf51b4,0x3f02b931,0x3f1882b9,0x3f28d9df,0x3f310572,0x3f415c99,0x3f4efa8e,0x3f5f51b4,0x3f800000,0x3f8d9df5,0x3f9b3bea,0x3fa8d9df,0x3fb677d4,0x3fc415ca};
 __builtin_memcpy(ScRastral::s_followStaffFloat,bits,64);
 return x0; // Original x0 is untouched; source-level return type is not recovered.
}
