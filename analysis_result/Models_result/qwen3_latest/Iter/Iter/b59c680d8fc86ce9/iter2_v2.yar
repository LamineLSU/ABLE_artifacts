rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 } // CMP EAX, 01h + JE (evasion check)
        $pattern1 = { A8 01 75 10 }     // TEST AL, 01h + JNE (evasion check)
        $pattern2 = { FF 15 ?? F1 42 00 } // Call to TerminateProcess (exit decision)

    condition:
        any of them
}