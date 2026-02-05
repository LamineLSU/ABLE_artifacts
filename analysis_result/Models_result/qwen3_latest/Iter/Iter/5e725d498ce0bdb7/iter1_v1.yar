rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { A9 C5 1E B6 55 }
        $pattern1 = { 8B 45 08 8B 48 14 }
        $pattern2 = { FF D2 C3 }

    condition:
        any of them
}