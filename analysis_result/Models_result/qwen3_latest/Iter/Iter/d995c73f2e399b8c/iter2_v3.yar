rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D2 31 82 4F 9B CB 55 }
        $pattern1 = { E8 44 09 00 00 }
        $pattern2 = { 8B 45 08 8B 48 10 }

    condition:
        any of them
}