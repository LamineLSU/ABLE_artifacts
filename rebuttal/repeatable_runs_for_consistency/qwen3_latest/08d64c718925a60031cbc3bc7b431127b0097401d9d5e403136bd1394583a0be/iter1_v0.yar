rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 74 54 41 00 85 C0 74 10 }  // CALL IsWindowVisible + TEST EAX + JE
        $pattern1 = { FF 15 3C 51 41 00 }                // CALL ExitProcess
        $pattern2 = { 68 00 00 00 00 FF 15 3C 51 41 00 }  // PUSH 00h + CALL ExitProcess

    condition:
        any of them
}