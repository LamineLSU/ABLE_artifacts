rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 E8 ?? ?? ?? ?? }  // cmp eax, 01h + call (sandbox check)
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }     // push eax + call TerminateProcess
        $pattern2 = { C1 E8 08 A8 01 75 ?? }      // shr eax, 08h + test al + jne (evasion logic)

    condition:
        any of them
}