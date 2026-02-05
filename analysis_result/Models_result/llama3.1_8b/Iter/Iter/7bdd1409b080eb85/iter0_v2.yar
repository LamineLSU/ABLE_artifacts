rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 F4 63 45 00 68 ?? ?? ?? ?? }
        $pattern1 = { FF 74 24 04 8B ?? ?? ?? }
        $pattern2 = { FF 15 8C 62 45 00 E8 ?? ?? ?? }

    condition:
        any of them
}