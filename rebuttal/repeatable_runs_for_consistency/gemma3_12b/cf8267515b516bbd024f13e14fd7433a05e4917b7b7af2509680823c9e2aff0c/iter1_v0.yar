rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 3C BF 00 D3 C5 21 28 B1 67 BD 06 55 }
        $pattern1 = { 8B 45 08 8B 48 10 56 6A 35 6A 00 51 8D B0 74 0C 00 00 56 }
        $pattern2 = { 8B 45 08 8B 88 14 0A 00 00 56 6A 36 6A 00 51 8D B0 80 0C 00 00 }

    condition:
        any of them
}