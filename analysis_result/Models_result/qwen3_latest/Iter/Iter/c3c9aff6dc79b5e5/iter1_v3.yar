rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 70 44 41 00 85 C0 74 10 }
        $pattern1 = { 83 7D 10 00 75 32 }
        $pattern2 = { 6A 02 FF 15 28 44 41 00 FF 15 38 41 41 00 }

    condition:
        any of them
}