rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 51 51 E8 ?? ?? ?? ?? }  // Push ecx, Push ecx, Call (offset)
        $pattern1 = { 56 E8 ?? ?? ?? ?? }      // Push esi, Call (offset)
        $pattern2 = { B9 00 00 42 00 FF 15 ?? ?? ?? ?? }  // Mov ecx, Call GetModuleHandleA (offset)

    condition:
        any of them
}