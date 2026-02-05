rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 6A 00 6A 00 68 48 75 44 00 FF 15 00 40 44 00 }
        $pattern1 = { 83 C4 18 53 89 9D 98 FE FF FF 89 9D 9C FE FF FF }
        $pattern2 = { FF 15 84 74 45 00 8D 85 94 FE FF FF 53 50 }

    condition:
        any of them
}