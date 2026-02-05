rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? }
        $pattern1 = { 74 ?? ?? ?? ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { FF 15 10 61 3A 00 CA DD 00 3A 61 10 FF 15 14 61 3A 00 CA DD 00 3A 61 14 }

    condition:
        any of them
}