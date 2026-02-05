rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 04 68 00 30 00 00 BE 70 5D 1E 00 56 6A 00 FF 15 88 F0 42 00 }
        $pattern1 = { 83 F8 11 74 05 8B C0 }
        $pattern2 = { 85 C9 0B C0 F8 58 85 FF }

    condition:
        any of them
}