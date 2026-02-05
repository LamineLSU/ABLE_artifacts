rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 11 74 05 8B }
        $pattern1 = { 68 C0 9E E6 05 6A 00 56 }
        $pattern2 = { FF 15 48 50 44 00 83 }

    condition:
        any of them
}