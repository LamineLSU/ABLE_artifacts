rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using consistent patterns in the trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 40 68 EA DD EA 68 }
        $pattern1 = { C1 E8 08 EA 08 }
        $pattern2 = { 75 10 00 78 65 5A }

    condition:
        any of them
}