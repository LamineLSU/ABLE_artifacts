rule Bypass_Sample
{
    meta:
        description = "Evasion bypass exploiting dynamic function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    patterns:
        pattern0: {
            start hex: 0x4C,
            bytes: E8 A4 ??
            comment: Dynamic call with unknown address
        },
        pattern1: {
            start hex: 0x5A,
            bytes: E8 C8 ??
            comment: Another dynamic call
        },
        pattern2: {
            start hex: 0x6E,
            bytes: 75 EE JZ ??
            comment: Unconditional jump over comparison check
        }
}