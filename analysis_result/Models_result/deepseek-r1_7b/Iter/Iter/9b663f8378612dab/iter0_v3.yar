rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting different attacker checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 74 ?? ?? 75 ?? ?? ?? ?? 00 00 00 }
        $pattern2 = { FF 08 B8 ?? ?? ?? ?? 6A ?? }

    condition:
        any of them
}