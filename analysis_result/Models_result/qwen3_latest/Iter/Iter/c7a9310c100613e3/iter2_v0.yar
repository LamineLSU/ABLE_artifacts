rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 66 83 F8 01 75 20 }  // CMP AX, 0001h + JNE (first check)
        $pattern1 = { 66 83 F8 01 75 0D }  // CMP AX, 0001h + JNE (second check)
        $pattern2 = { FF 15 ?? ?? ?? ?? }  // ExitProcess call (exit decision)

    condition:
        any of them
}