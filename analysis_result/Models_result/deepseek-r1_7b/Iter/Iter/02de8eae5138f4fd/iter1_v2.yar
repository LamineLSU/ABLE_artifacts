rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 45 ?? 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 74 ?? 1A ?? 3F ?? ?? ?? ?? ?? ?? ?? ?? 8E 2C 8D 79 6F }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}