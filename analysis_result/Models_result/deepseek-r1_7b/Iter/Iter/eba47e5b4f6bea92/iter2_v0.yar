rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting test+je at early offset"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 30 61 7A 30 61 7C }  // test eax, je offset

    condition:
        any
}