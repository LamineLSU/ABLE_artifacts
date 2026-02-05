rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 8B 40 68 }  // FS register access + offset
        $pattern1 = { 8B 40 68 C1 E8 08 A8 01 } // Offset check + test
        $pattern2 = { 64 A1 30 00 00 00 74 20 } // FS register access + conditional jump

    condition:
        any of them
}