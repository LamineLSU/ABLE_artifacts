rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 }
        $pattern2 = { 90 E8 95 DB 43 74 }

    condition:
        any of them
}