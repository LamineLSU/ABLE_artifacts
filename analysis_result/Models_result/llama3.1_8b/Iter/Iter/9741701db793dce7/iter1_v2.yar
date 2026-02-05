rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$p1+0,action0=skip,bp1=$p2+0,action1=skip,bp2=$p3+0,action2=skip,count=0"

    strings:
        $p1 = { 55 8B EC B9 F8 26 43 00 E8 43 1C 00 00 }
        $p2 = { 83 F8 01 74 12 8B 4D F8 }
        $p3 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}