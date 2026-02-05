rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 74 64 45 00 89 45 FC 50 83 F8 11 }
        $pattern1 = { 6A 00 83 7D FC 00 74 2F 8A C0 }
        $pattern2 = { FF 15 9C 63 45 00 6A 00 FF 75 FC }

    condition:
        any of them
}