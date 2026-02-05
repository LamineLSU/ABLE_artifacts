rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 64 48 D1 00 FF 15 20 41 D1 00 } // From Trace 1 & 5: Push, Call
        $pattern1 = { 68 70 48 D1 00 50 FF 15 1C 42 D1 00 } // From Trace 1 & 5: Push, Call, Push, Call
        $pattern2 = { 68 10 20 00 00 FF D0 68 A4 48 D1 00 } // From Trace 1 & 5: Push, Call, Call, Push

    condition:
        any of them
}