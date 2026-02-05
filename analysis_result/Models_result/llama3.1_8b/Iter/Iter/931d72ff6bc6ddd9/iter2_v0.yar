rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$p0+0,action0=skip,bp1=$p1+0,action1=skip,bp2=$p2+0,action2=skip,count=0"

    strings:
        $p0 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $p1 = { 83 F8 01 74 12 8B 4D F8 }
        $p2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}