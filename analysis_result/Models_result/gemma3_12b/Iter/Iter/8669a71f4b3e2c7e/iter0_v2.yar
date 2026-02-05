rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 B5 A9 D8 59 FF 75 08 FF 15 8C E1 B6 00 }
        $pattern1 = { 00 40 E7 EE 8B FF 55 8B EC FF 75 08 }
        $pattern2 = { 00 40 E7 EE 8B FF 55 8B EC FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}