rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 94 FD FF FF }
        $pattern1 = { 8D 95 78 FD FF FF }
        $pattern2 = { 8D 85 94 FD FF FF }

    condition:
        any of them
}