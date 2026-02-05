rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - target exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 EE 82 FF FF 85 C0 74 0E }
        $pattern1 = { E8 B7 F7 FF FF 3D 00 10 00 00 0F 82 }
        $pattern2 = { FF 15 14 28 43 00 6A 00 00 00 00 00 }
    condition:
        (any of them)
}