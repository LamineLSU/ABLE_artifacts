rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 57 5C 8B F2 59 50 51 52 53 8B 55 14 8B 55 10 8B 45 0C 8B 45 08 83 C4 14 }
        $pattern1 = { 75 CF 01 18 7B 4D 4D 55 8B EC 8B 45 08 8B 48 10 56 6A 35 6A 00 51 8D B0 74 0C 00 00 }
        $pattern2 = { 56 50 55 8B EC 8B 45 08 8B 48 10 56 6A 35 6A 00 51 8D B0 74 0C 00 00 E8 44 09 00 00 }

    condition:
        any of them
}