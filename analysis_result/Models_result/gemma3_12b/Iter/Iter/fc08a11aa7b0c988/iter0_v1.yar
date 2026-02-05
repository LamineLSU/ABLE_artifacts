rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 3C 04 41 00 FF 75 08 FF 15 38 04 41 00 6A 00 FF 75 08 6A 00 FF 75 FC }
        $pattern1 = { FF 35 AC 5B 41 00 FF 15 64 04 41 00 85 C0 74 10 6A 00 FF 35 AC 5B 41 00 FF 15 0C 04 41 00 }
        $pattern2 = { FF 35 A0 5B 41 00 FF 15 34 04 41 00 EB 38 FF 35 AC 5B 41 00 FF 15 0C 04 41 00 EB 38 }

    condition:
        any of them
}