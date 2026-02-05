rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 ?? 05 00 00 }  // test+je+call (evasion check)
        $pattern1 = { FF 15 88 A0 02 00 }           // call to CloseHandle (cleanup check)
        $pattern2 = { A1 88 85 02 00 85 C0 74 07 }   // mov+test+je (state validation)

    condition:
        any of them
}