rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 81 D1 74 0A 8D 4C 24 18 }
        $pattern1 = { E8 1C 3C 03 00 85 C0 74 0A }
        $pattern2 = { 6A 05 6A 00 50 68 50 80 85 00 }

    condition:
        any of them
}