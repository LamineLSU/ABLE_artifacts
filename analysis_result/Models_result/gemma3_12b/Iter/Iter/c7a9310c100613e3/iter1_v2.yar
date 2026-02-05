rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 66 83 F8 01 75 20 }
        $pattern1 = { 66 83 F8 01 75 0D }
        $pattern2 = { 6A 00 FF 15 38 51 A1 03 }

    condition:
        any of them
}