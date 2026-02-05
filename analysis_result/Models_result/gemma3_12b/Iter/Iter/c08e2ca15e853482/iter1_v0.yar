rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 04 68 00 30 00 00 68 C0 41 C8 17 6A 00 FF 15 08 50 44 00 }
        $pattern1 = { 83 E4 F8 83 EC 48 6A 40 8D 44 24 04 6A 00 50 E8 CD D3 01 00 83 C4 0C }
        $pattern2 = { 6A 00 6A 40 68 00 30 00 00 68 D0 07 00 00 6A 00 56 E8 CD D3 01 00 }

    condition:
        any of them
}