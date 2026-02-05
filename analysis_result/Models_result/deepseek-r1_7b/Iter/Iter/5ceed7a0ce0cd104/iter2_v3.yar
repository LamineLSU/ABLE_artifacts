rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 41 56 73 C8 C1 E8 A8 }
        $pattern1 = { FF 15 3C F1 42 00 E8 B9 }
        $pattern2 = { FF 15 A0 F1 42 00 6D 79 }

    condition:
        (matches $pattern0) || (matches $pattern1) || (matches $pattern2)
}