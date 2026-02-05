rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 8B 45 08 8B 48 10 56 6A 35 6A 00 51 8D B0 74 0C 00 00 56 50 E8 44 09 00 00 FF D0 }
        $pattern1 = { F6 D2 8B 4D 10 56 50 E8 44 09 00 00 FF D2 56 50 E8 44 09 00 00 8B 55 0C 8B 06 83 C4 14 52 }
        $pattern2 = { 85 C0 74 07 51 8D B0 74 0C 00 00 56 50 E8 44 09 00 00 8B 55 0C 8B 06 83 C4 14 52 }

    condition:
        any of them
}