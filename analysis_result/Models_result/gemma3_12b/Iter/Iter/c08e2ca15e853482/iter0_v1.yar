rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 44 24 04 6A 00 50 E8 CD D3 01 00 }
        $pattern1 = { 85 C0 75 1D 8B 44 24 0C }
        $pattern2 = { 85 C0 75 3A 8D 85 F4 FE FF FF }

    condition:
        any of them
}