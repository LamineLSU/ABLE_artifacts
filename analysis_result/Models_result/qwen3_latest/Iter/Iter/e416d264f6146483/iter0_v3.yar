rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B D0 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // mov edx, eax + call + push + call
        $pattern1 = { B9 01 00 00 80 E8 ?? ?? ?? ?? 83 C4 20 }  // mov ecx, 80000001h + call + add esp
        $pattern2 = { 83 C4 20 8D 4C 24 10 E8 ?? ?? ?? ?? }  // add esp + lea + call

    condition:
        any of them
}