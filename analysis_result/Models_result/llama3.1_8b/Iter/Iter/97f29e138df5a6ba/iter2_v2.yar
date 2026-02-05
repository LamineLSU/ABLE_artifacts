rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 D1 65 66 E8 95 DB 0D 74 }
        $pattern1 = { 00 51 65 67 E8 94 DB 8D 74 }
        $pattern2 = { 64 A1 30 00 00 00 8B 40 68 }

    condition:
        any of them
}