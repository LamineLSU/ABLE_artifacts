rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern1 = { 8B 91 80 00 00 00 ED DD EC 00 00 00 80 }
        $pattern2 = { FF 15 5C C2 4C 00 CA DD 00 4C C2 5C }

    condition:
        any of them
}