rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 11 74 05 8B C0 }
        $pattern1 = { 85 C9 0B C0 F8 58 85 FF 74 27 }
        $pattern2 = { FF 15 88 00 26 00 }

    condition:
        any of them
}