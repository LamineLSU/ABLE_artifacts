rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }  // ExitProcess call with surrounding context
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }            // TerminateProcess call with push
        $pattern2 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }   // Initial check with call and cmp/jmp

    condition:
        any of them
}