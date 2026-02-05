rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 74 1A ?? 0F 84 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 85 C0 74 1A ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}