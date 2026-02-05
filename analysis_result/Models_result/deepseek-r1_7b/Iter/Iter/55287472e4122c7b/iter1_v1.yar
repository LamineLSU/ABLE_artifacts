rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - more specific"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 89 45 FC DD EB 04 EA }
        $pattern1 = { 83 C0 EA EA }
        $pattern2 = { FC CD }
}

condition:
    any of them
}