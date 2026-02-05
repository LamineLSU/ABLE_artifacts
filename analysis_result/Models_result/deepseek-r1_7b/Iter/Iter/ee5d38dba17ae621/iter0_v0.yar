rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting suspicious points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 56 EB 56 C3 }
        $pattern1 = { 8B 45 ?? 8B ?? ?? 83 C4 ?? ?? ?? ?? 8B 45 ?? 8B ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 83 C4 ?? ?? ?? }

    condition:
        any of them
}