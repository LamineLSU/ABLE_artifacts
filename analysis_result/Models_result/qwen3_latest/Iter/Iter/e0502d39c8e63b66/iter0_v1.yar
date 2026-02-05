rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 51 51 E8 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? BA 3C 00 42 00 B9 00 00 42 00 E8 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 56 }

    condition:
        any of them
}