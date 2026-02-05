rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific exit check bypass points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 81 C4 00 FC FF FF E8 95 10 00 } // Match after call to test EAX
        $pattern1 = { FF B5 A4 FC FF FF FF 35 C5 40 40 00 E8 57 03 00 00 } // Conditional check before exit
        $pattern2 = { 6A 00 6A 00 FF 35 C5 40 40 00 } // Early call bypass

    condition:
        (any of the patterns match)
}