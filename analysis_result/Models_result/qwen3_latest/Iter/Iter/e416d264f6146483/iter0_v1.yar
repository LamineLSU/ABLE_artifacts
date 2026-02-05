rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 20 8D 4C 24 10 }
        $pattern2 = { E8 ?? ?? ?? ?? 8B D0 B9 01 00 00 80 }

    condition:
        any of them
}