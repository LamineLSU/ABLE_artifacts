rule bypass_sample_evolved
{
    meta:
        description = "Evasion bypass based on exit check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:

    condition:
        any of them
}