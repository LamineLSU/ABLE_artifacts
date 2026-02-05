rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 83 F8 11 74 05 8B F0 50 FF 15 50 50 44 00 }
        $pattern1 = { 8D 44 24 04 6A 00 50 E8 CD D3 01 00 83 C4 0C 53 8A C9 8A C9 FC FF 15 50 50 44 00 }
        $pattern2 = { 6A 3C 8D 85 94 FE FF FF 53 50 E8 CD D3 01 00 68 04 01 00 00 8D 8D EC FE FF FF 53 51 E8 CD D3 01 00 }

    condition:
        any of them
}