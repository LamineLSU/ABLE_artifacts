rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 89 9D 98 FE FF FF 89 9D 9C FE FF FF 89 8D A8 FE FF FF }
        $pattern1 = { 6A 3C 8D 85 94 FE FF FF 53 50 E8 B1 25 02 00 }
        $pattern2 = { 89 9D B0 FE FF FF 89 9D B4 FE FF FF FF 15 84 75 45 00 }

    condition:
        any of them
}