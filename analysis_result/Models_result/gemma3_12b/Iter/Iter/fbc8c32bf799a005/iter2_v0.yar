rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 97 00 00 00 75 DD }
        $pattern1 = { 81 D1 89 E0 8D 4C 24 18 }
        $pattern2 = { 6A 05 6A 00 50 68 50 80 85 00 }

    condition:
        any of them
}