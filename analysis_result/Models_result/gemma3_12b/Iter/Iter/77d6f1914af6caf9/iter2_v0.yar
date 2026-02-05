rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 57 53 56 6A 40 BE 00 30 00 00 }
        $pattern1 = { 57 56 68 D0 07 00 00 57 FF 15 94 37 38 00 }
        $pattern2 = { 50 FF 15 58 37 38 00 85 C0 75 07 }

    condition:
        any of them
}