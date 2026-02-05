rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting early checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 75 ?? 8B ?? ?? ?? ?? 5C 8B ?? }

    condition:
        any of them
}