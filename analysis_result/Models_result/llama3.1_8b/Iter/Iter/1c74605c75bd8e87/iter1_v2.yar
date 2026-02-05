rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B E5 E8 ?? ?? ?? ?? 83 EC ?? 84 C0 }
        $pattern1 = { 33 C9 8B D3 E8 ?? ?? ?? ?? 89 F8 }
        $pattern2 = { 83 C4 04 E8 ?? ?? ?? ?? 59 }

    condition:
        any of them
}