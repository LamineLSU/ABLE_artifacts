rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C4 53 E8 ?? ?? ?? ?? 83 F9 FF 74 17 }
        $pattern1 = { 6A 01 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 83 C4 08 8B D8 FF 35 ?? ?? ?? ?? }

    condition:
        any of them
}