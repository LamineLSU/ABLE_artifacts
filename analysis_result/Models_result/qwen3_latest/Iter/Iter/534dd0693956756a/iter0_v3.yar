rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 ?? ?? ?? ?? }  // Skip TerminateProcess call
        $pattern1 = { E8 0B 00 00 00 59 FF 15 ?? ?? ?? ?? }  // Skip ExitProcess call chain
        $pattern2 = { 8B EC E8 ?? ?? ?? ?? }  // Skip initial evasion check call

    condition:
        any of them
}