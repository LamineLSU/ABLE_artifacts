rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 66 83 F8 01 75 20 }
        $pattern1 = { FF 15 80 51 A1 03 }
        $pattern2 = { FF 15 34 51 A1 03 }

    condition:
        any of them
}