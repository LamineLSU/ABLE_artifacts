rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 11 74 05 8B C0 FC 85 C9 }
        $pattern1 = { 83 7D FC 00 74 2F }
        $pattern2 = { 68 C0 9E E6 05 6A 00 FF 75 FC }

    condition:
        any of them
}