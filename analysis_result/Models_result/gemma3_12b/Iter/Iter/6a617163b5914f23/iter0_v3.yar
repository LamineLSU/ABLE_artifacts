rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 84 75 45 00 8D 95 94 FE FF FF 8D 8D EC FE FF FF 52 C7 85 94 FE FF FF 3C 00 00 00 }
        $pattern1 = { FF 15 84 74 45 00 6A 3C 8D 85 94 FE FF FF 53 50 E8 B1 25 02 00 }
        $pattern2 = { 68 48 75 44 00 FF 15 00 40 44 00 8B F0 6A 08 56 FF 15 04 40 44 00 56 6A 00 8B F8 }

    condition:
        any of them
}