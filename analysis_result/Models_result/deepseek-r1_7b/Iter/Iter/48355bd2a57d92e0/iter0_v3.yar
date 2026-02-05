rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection using patterns from exit process calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 B3 A2 D6 75 D6 } // Bypasses a conditional jump after the call in TRACE //1
        $pattern1 = { 00 B7 34 F4 FF 75 08 E8 0B 00 00 00 } // Bypasses a memory address check in TRACE //2
        $pattern2 = { 6A 03 00 B3 A2 FF FF 15 84 A0 B8 00 } // Bypasses an unconditional call in TRACE //1

    condition:
        any of them
}