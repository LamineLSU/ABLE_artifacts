rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [4 1B 8D 1, 41 B8 DB ] }
        $pattern1 = { [4 1B 8E C, 41 B8 EE ] }
        $pattern2 = { [4 1B 90 C] }

    condition:
        any of them
}