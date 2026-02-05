rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting early conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6-20 bytes with wildcards matching early conditional call followed by TEST EAX and JE }
        $pattern1 = { 6-20 bytes matching the ExitProcess call at specific offset with potential condition }
        $pattern2 = { 6-20 bytes for another known API check }
    count = 3
}