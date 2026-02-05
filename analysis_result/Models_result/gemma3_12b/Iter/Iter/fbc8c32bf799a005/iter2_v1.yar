rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 97 00 00 00 75 DD }
        $pattern1 = { 81 D1 85 C0 74 06 }
        $pattern2 = { E8 D6 39 00 00 85 C0 }

    condition:
        any of them
}