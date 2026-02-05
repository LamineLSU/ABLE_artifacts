rule Bypass_Sample_Evolved
{
    meta:
        description = "Bypass early conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B ?? }
        $pattern1 = { 83 F8 74 12 6A 5B ?? }
        $pattern2 = { E8 25 74 12 6A 5B ?? }

    condition:
        any of them
}