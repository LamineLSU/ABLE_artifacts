rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 0C 83 C4 00 00 E8 ?? ?? ?? ?? }
        $pattern1 = { FF F0 00 00 00 00 7A A9 ?? ?? ?? }
        $pattern2 = { E8 B5 8B EC 00 00 3F F9 ?? 00 00 }

    condition:
        any of them
}