rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 ?? 05 00 00 }  // test/je + call (first check)
        $pattern1 = { E8 74 FA FF FF 85 C0 }         // call + test (secondary check)
        $pattern2 = { FF 15 2C A1 9D 00 }            // ExitProcess call (6-byte signature)

    condition:
        any of them
}