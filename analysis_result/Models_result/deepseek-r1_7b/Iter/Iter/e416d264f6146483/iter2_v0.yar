rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting multiple suspicious points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ED 06 5E 0C 30 ?? 74 1A }
        $pattern1 = { E8 ?? 8D ?? ?? 8B ?? 00 ?? 45 ?? ?? 74 ?? ?? ?? 8B ?? F0 ?? FF ?? F8 ?? FC ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}