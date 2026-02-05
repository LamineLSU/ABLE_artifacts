rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting API calls with conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 56 57 6A 04 68 00 30 00 00 57 56 FF 15 88 00 26 00 8B F8 50 83 F8 11 74 05 74 27 }
        $pattern1 = { FC F8 5C 85 FF 74 27 }
        $pattern2 = { 6A 00 5B 8B C0 FC 5E }

    condition:
        any of them
}