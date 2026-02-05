rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 D8 54 41 00 00 ?? 83 F8 01 74 12 }
        $pattern1 = { FF 15 9C 54 41 00 6A 00 FF 75 08 6A 00 }
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}