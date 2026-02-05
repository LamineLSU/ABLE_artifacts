rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 04 68 00 30 00 00 68 C0 41 C8 17 }
        $pattern1 = { 83 F8 11 74 05 8B C0 }
        $pattern2 = { 68 C0 9E E6 05 6A 00 56 E8 CD D3 01 }

    condition:
        any of them
}