rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 40 E7 F6 E8 C8 FF FF FF }
        $pattern1 = { 00 40 E7 FF FF 15 AC B0 41 00 }
        $pattern2 = { 00 B2 A9 DC FF 15 8C E1 B3 00 }

    condition:
        any of them
}