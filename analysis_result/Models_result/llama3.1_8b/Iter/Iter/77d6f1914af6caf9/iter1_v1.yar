rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 83 EC 48 53 56 57 }
        $pattern1 = { E8 DE 0D 00 00 CA 00 10 DD 84 }
        $pattern2 = { 68 D9 FB 10 00 DD 10 FB D9 }

    condition:
        any of them
}