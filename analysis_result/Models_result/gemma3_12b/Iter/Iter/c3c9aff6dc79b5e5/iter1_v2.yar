rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 FF 75 08 6A 00 FF 75 FC }
        $pattern1 = { 85 C0 74 10 6A 00 FF 35 D4 B0 41 00 }
        $pattern2 = { 6A 09 FF 35 D4 B0 41 00 FF 15 90 44 41 00 }

    condition:
        any of them
}