rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule targeting specific exit call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [6-20 bytes with wildcards] }
        $pattern1 = { [6-20 bytes - DIFFERENT sequence] }
        $pattern2 = { [6-20 bytes - DIFFERENT sequence] }

    condition:
        any of them
}