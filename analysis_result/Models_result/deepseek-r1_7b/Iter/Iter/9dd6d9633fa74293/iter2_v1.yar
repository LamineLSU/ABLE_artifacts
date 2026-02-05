rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass mechanism detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=trace_continuation,bp2=$pattern2+0,action2=trace_continuation,count=0"

    strings:
        $pattern0 = { ?? }
        $pattern1 = { ?? }
        $pattern2 = { ?? }

    condition:
        any of them
}