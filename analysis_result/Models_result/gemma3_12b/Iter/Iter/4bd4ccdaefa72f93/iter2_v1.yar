rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 8D 4C 24 60 48 89 74 24 30 45 33 C9 89 74 24 28 }
        $pattern1 = { 74 4E 4C 8D 8D 90 01 00 00 48 89 9D 98 01 00 00 }
        $pattern2 = { FF 15 B2 0E 00 00 48 8B F8 48 83 F8 FF }

    condition:
        any of them
}