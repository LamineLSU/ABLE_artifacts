rule Bypass_Sample_01
{
    meta:
        description = "Evasion bypass rule - Pattern 0"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC 5D }

    condition:
        any of them
}