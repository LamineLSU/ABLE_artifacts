rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 89 9D B4 FE FF FF 89 9D B0 FE FF FF 89 9D B8 FE FF FF FF 15 84 74 45 00 }
        $pattern1 = { 81 FF 99 02 00 00 5F 5E 7D 08 }
        $pattern2 = { 6A 3C 8D 85 94 FE FF FF 53 50 E8 B1 25 02 00 }

    condition:
        any of them
}