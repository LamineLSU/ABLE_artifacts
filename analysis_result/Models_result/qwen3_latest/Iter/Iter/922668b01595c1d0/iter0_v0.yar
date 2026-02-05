rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }  // Call + cmp + je (sandbox check)
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }            // Push + call TerminateProcess
        $pattern2 = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }   // Pop + push + call ExitProcess

    condition:
        all of them
}