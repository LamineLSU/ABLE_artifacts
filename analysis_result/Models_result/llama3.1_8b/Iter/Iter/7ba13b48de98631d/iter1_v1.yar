rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8 ?? ?? ?? ?? 83 F9 ?? 75 ?? 8B 45 ?? }
        $pattern2 = { 65 ?? 66 ?? 67 ?? 8B ?? ?? ?? 6A ?? }

    condition:
        any of them
}