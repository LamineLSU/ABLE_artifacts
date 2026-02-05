rule Bypass_Sample
{
    meta:
        description = "Evasion bypass for conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E9 ?? }
        $pattern1 = { 75 ?? ?? ?? EA EA ?? }
        $pattern2 = { ?? ?? ?? EA EA ?? }

    condition:
        any of them
}