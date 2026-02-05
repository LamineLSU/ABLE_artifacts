rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 91 8C 00 00 00 FF D2 }
        $pattern1 = { 8B 45 D8 50 8B 4D 08 }
        $pattern2 = { 8B 4D DC 51 8B 55 08 }

    condition:
        any of them
}