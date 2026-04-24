rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 56 57 33 DB 53 6A 40 }
        $pattern1 = { 50 FF 15 E0 74 44 00 6A 3C 8D 85 EC FE FF FF }
        $pattern2 = { 53 56 57 33 F6 56 56 56 68 14 80 43 00 }

    condition:
        any of them
}