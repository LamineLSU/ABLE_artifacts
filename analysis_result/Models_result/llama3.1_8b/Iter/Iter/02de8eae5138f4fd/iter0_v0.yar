rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
        $pattern1 = { 8B EC 85 C0 74 ?? 8B D8 B9 C8 00 00 }
        $pattern2 = { F3 AF 75 EF FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? }

    condition:
        any of them
}