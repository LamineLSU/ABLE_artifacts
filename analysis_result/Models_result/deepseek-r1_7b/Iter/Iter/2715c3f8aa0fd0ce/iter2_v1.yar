rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting conditional exits"
        cape_options = "bp0=$pattern0+0,bp1=$pattern1+0,bp2=$pattern2+0,action0=skip,action1=skip,action2=skip,count=0"

    strings:
        $pattern0 = { C1 08 FF A8 01 74 }
        $pattern1 = { E8 F7 25 00 00 FF FF 3C 40 }
        $pattern2 = { 64 3C 00 00 00 05 99 00 00 00 00 00 00 18 75 08 }
    condition:
        any of them
}