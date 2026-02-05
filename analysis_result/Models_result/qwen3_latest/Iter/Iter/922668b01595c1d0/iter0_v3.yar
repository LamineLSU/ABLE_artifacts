rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 FF 75 08 FF 15 3C F1 42 00 50 FF 15 40 F1 42 00 }  // cmp eax,01h + je + push + call GetCurrentProcess + push + call TerminateProcess
        $pattern1 = { C1 E8 08 A8 01 75 10 FF 75 08 E8 0B 00 00 00 }  // shr eax,08h + test al,01h + jne + push + call
        $pattern2 = { FF 75 08 FF 15 A0 F1 42 00 }  // push + call ExitProcess

    condition:
        any of them
}