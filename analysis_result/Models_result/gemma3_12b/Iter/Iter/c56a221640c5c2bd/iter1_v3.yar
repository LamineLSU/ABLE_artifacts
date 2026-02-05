rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 88 C4 09 00 00 }
        $pattern1 = { 56 6A 36 6A 00 51 8D B0 A8 0A 00 00 }
        $pattern2 = { 8B 55 0C 8B 06 83 C4 14 52 }

    condition:
        any of them
}