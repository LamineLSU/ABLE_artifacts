rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,count=0"

    strings:
        $pattern0 = { 6A 00 8B 45 FC FF 15 D8 54 41 00 }
        $pattern1 = { 85 C0 74 10 6A 00 FF 35 FC C1 41 00 }
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 }

    condition:
        any of them
}