rule Bypass_Sample_Evaded
{
    meta:
        description = "Bypass sample using early exits with test and jump"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 }
        $pattern1 = { 20 }
        $pattern2 = { 20 }

    condition:
        any of them
}