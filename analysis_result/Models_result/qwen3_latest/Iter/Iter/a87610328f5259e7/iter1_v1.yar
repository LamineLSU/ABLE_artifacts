rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 } // CALL_TEST_JE
        $pattern1 = { FF 15 88 A0 D2 00 FF 15 2C A1 D2 00 }         // API_CHECK
        $pattern2 = { 33 DB BA 21 05 00 00 }                         // DEBUG_CHECK

    condition:
        any of them
}