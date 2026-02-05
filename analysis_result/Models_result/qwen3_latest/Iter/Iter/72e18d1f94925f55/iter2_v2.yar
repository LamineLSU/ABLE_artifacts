rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 ?? }  // 10 bytes: call, cmp, je
        $pattern1 = { C1 E8 08 A8 01 75 ?? }              // 7 bytes: shr, test, jne
        $pattern2 = { E8 ?? ?? ?? ?? 90 59 50 }         // 8 bytes: call, nop, pop, push

    condition:
        any of them
}