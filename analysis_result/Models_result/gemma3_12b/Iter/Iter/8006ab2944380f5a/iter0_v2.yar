rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 83 EC 10 53 56 8B 75 08 8B 45 0C 8B 06 52 FF D0 }
        $pattern1 = { 55 8B EC 83 EC 10 53 56 8B 75 08 8B 45 10 8B 4D 0C 83 C4 14 52 FF D0 }
        $pattern2 = { 55 8B EC 83 EC 10 53 56 8B 75 08 8B 45 08 8B 88 D8 02 00 00 56 6A 36 6A 00 51 8D B0 A8 0A 00 00 56 50 E8 24 13 00 }

    condition:
        any of them
}