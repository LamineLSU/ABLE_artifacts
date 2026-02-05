rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B F8 50 83 F8 11 74 05 }
        $pattern1 = { 0B C0 F8 58 85 C9 74 27 }
        $pattern2 = { 57 56 57 FF 15 54 00 26 00 }

    condition:
        any of them
}