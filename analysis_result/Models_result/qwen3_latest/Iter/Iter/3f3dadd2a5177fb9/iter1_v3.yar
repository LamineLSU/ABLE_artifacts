rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }  // call + cmp eax,01 + je
        $pattern1 = { C1 E8 08 A8 01 75 10 }               // shr + test al,01 + jne
        $pattern2 = { 50 FF 15 ?? ?? ?? ?? }            // push + call TerminateProcess

    condition:
        any of them
}