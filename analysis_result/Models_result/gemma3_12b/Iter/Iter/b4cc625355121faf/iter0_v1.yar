rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 8B 85 F0 FE FF FF 8D 95 F0 FE FF FF 89 9D F0 FE FF FF }
        $pattern2 = { E9 B5 FC FF FF 33 DB BA 21 05 00 00 53 6A 40 53 68 40 11 97 00 }

    condition:
        any of them
}