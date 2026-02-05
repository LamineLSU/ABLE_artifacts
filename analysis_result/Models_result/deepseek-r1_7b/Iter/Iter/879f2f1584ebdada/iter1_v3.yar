rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit handlers"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 81 74 00 E8 25 05 00 }
        $pattern1 = { E9 B5 FC FF FF 1A 3E 82 50 50 }
        $pattern2 = { 8D 43 01 7A 5B 03 E8 4B 17 00 }
    condition:
        any of them
}