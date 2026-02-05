rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 F4 FE FF FF 50 8D 8D F8 FE FF FF }
        $pattern1 = { 6A 3C 8D 85 94 FE FF FF 53 50 E8 9D D9 01 00 }
        $pattern2 = { FF 15 84 95 45 00 6A 3C 8D 85 94 FE FF FF 53 50 }

    condition:
        any of them
}