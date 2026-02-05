rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C1 FF FF FF 8B 45 FC }
        $pattern1 = { FF 15 5C C2 4C 00 }
        $pattern2 = { 8B 91 80 00 00 00 }

    condition:
        any of them
}