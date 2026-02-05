rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D B0 74 0C 00 00 ?? ?? ?? ?? 56 50 }
        $pattern1 = { 8D B0 7C 0C 00 00 ?? ?? ?? ?? 56 50 }
        $pattern2 = { 55 ?? 8B EC 8B 45 08 }

    condition:
        any of them
}