rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // ExitProcess call with push ebp+08h
        $pattern1 = { 36 50 FF 15 ?? ?? ?? ?? }     // TerminateProcess call with push eax
        $pattern2 = { E8 ?? ?? ?? ?? 83 F8 01 }     // Initial check call and cmp eax, 01h

    condition:
        all of them
}