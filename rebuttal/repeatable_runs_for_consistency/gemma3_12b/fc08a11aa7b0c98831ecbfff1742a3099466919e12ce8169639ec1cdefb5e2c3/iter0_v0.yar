rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 FF 75 08 FF 15 38 04 41 00 }
        $pattern1 = { FF 35 AC 5B 41 00 FF 15 0C 04 41 00 }
        $pattern2 = { 6A 00 FF 15 24 01 41 00 FF 15 30 04 41 00 }

    condition:
        any of them
}