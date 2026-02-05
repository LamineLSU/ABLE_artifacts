rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 7D FC 00 75 08 }  // cmp+je before exit decision
        $pattern1 = { FF 15 ?? ?? ?? ?? }   // ExitProcess call (address varies)
        $pattern2 = { 51 C7 45 FC 00 00 00 00 }  // push ecx + initial memory setup

    condition:
        any of them
}