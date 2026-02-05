rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific stack checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 ?? }  // Specific comparison and jump
        $pattern1 = { 6C 5E C9 FF FF FF }   // Immediate word check after call
        $pattern2 = { ?? E8 C8 C1 C1 C1 C1 } // Pseudo-instruction bypass

    condition:
        any of them
}