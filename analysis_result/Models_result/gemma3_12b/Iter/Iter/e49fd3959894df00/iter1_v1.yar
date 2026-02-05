rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 56 57 33 DB 53 6A 40 }
        $pattern1 = { 00 40 10 21 85 C0 75 07 }
        $pattern2 = { 00 40 10 3F 83 F8 11 74 05 }

    condition:
        any of them
}