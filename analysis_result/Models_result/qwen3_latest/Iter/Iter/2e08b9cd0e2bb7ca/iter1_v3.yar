rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 E8 8E 07 00 00 }  // Push + call to ExitProcess
        $pattern1 = { 83 BD 60 F9 FF FF 01 75 23 }  // cmp + jne (decision logic)
        $pattern2 = { FF B5 80 F9 FF FF E8 C6 07 00 00 }  // push + call (indirect exit)

    condition:
        any of them
}