rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 25 05 00 00 } // TEST EAX, JE, CALL (evasion check)
        $pattern1 = { FF 15 2C A1 C7 00 }      // CALL ExitProcess (exit decision)
        $pattern2 = { 53 6A 40 53 68 40 11 C7 00 33 C9 E8 4B 17 00 00 } // PUSH/XOR/Call sequence

    condition:
        any of them
}