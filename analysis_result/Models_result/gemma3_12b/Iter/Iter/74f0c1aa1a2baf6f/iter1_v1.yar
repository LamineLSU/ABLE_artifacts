rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 E8 41 D1 00 }
        $pattern1 = { 8B C8 8A 01 3C 22 75 28 }
        $pattern2 = { 8D 41 01 80 FA 22 }

    condition:
        any of them
}