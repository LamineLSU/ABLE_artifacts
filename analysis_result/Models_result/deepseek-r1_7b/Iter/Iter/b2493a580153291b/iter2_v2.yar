rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 40 68 C1 E8 A8 01 75 10 }
        $pattern1 = { 3D 00 10 00 00 30 A8 02 75 10 }
        $pattern2 = { F8 4F 8B 40 68 C1 E8 A8 01 75 10 }
}

condition:
    any of them
}