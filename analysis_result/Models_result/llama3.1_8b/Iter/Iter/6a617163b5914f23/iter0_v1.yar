rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { C7 85 94 FE FF FF 3C 00 00 00 FF 15 20 75 45 00 8D 95 94 FE FF FF }
        $pattern1 = { 83 C4 18 C7 85 A0 FE FF FF 80 EB 44 00 C7 85 A4 FE FF FF A8 FA 44 00 }
        $pattern2 = { 53 50 E8 B1 25 02 00 }

    condition:
        any of them
}