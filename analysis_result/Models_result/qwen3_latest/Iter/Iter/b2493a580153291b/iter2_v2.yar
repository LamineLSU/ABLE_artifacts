rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 17 D0 00 00 83 F8 01 74 20 }  // CALL + CMP EAX + JE
        $pattern1 = { A8 01 75 10 }                // TEST AL + JNE
        $pattern2 = { FF 15 98 52 F4 00 }             // ExitProcess call

    condition:
        any of them
}