rule Bypass_Sample_Evolved
{
    meta:
        description = "Bypass ExitProcess by evading conditional checks on EAX"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 40 10 85 00 00 00 04 EC EC 00 40 10 23 }
        $pattern1 = { 40 10 D7 EB BE 48 CA DD 00 45 56 64 }
        $pattern2 = { 40 1E 9C 00 00 00 40 }

    condition:
        (any of the patterns match)
}