rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 45 }
        $pattern1 = { 74 ?? ?? ?? ?? FF C9 ?? ?? ?? ?? 3C }
        $pattern2 = { 8B ?? ?? ?? ?? 83 ?? 85 C0 ?? 8F 7F }

    condition:
        any of them
}