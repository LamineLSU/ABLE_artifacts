rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=halt,bp1=$pattern1+0,action1=halt,bp2=$pattern2+0,action2=halt,count=0"

    strings:
        $pattern0 = { E8 CD 3D 00 00 83 F8 01 74 20 }
        $pattern1 = { C1 E8 08 A8 01 75 10 }
        $pattern2 = { 90 50 E8 94 DB DD 73 }

    condition:
        all of them
}