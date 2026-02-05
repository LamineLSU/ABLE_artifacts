rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - focuses on specific exit call points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 33 61 83 E8 25 05 00 00 00 33 61 C5 5B 00 33 61 D4 5C }
        $pattern1 = { 00 33 61 E8 74 07 00 33 61 F1 FF 15 00 33 62 00 A1 2C }
        $pattern2 = { 00 33 61 D7 74 07 00 33 61 E8 74 07 00 33 62 0F E8 57 }

    condition:
        any of them
}