rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 8B 40 68 5C 1E 80 8A 80 17 51 }
        $pattern1 = { E8 12 35 81 04 FF 75 08 E8 11 35 81 04 FF 75 08 E8 0B 00 00 00 59 }
        $pattern2 = { E8 94 DB 19 75 CC E8 95 DB 13 75 69 0C }

    condition:
        any of them
}