rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific patterns from the trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 D0 5C E9 FF 15 E8 41 D1 00 8B C8 8A 01 3C 22 75 28 41 8A C2 84 D2 74 11 41 8A 11 84 C0 75 F5 8D 41 01 } // API_CHECK bypass
        $pattern1 = { 00 D0 5C EF 8B C8 8A 01 3C 22 75 28 41 8A C2 84 D2 74 11 41 8A 11 84 C0 75 F5 8D 41 01 } // CALL_TEST_JE bypass
        $pattern2 = { 00 D0 5D 69 FF 15 F0 41 D1 00 } // EVASION_TECHNIQUE bypass

    condition:
        any of them
}