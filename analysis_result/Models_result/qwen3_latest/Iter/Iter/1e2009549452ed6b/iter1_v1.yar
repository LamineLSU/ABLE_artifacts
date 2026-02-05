rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 50 A0 20 00 85 FF 74 39 }  // CALL_WAITFOR + TEST EDI + JE
        $pattern1 = { FF 15 84 A0 20 00 }                // CALL_EXITPROCESS
        $pattern2 = { FF 15 40 A0 20 00 }                // CALL_HEAPFREE

    condition:
        any of them
}