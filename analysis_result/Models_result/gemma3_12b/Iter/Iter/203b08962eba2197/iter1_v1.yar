rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 3C 8D 85 94 FE FF FF 53 50 E8 9D D9 01 00 }
        $pattern1 = { 8D 8D EC FE FF FF 53 51 83 C4 18 53 68 04 01 00 00 }
        $pattern2 = { 8D 8D EC FE FF FF 53 51 50 E8 9D D9 01 00 68 04 01 00 00 }

    condition:
        any of them
}