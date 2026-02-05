rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved to target exit-related conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 B3 A2 99 ED ED 00 B3 A2 9B 00 B3 A2 D6 }
        $pattern1 = { 00 B7 34 C8 EB 00 B7 34 CB E8 6A 3E 00 00 CA 00 B7 73 3A }
        $pattern2 = { 00 B3 A2 8D FF FF FF FF 00 B3 A2 8F 00 00 00 01 }

    condition:
        (any of them)
}