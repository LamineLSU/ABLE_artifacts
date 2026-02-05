rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule targeting exit decision checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 20 shr eax,08h jne 0041B908h }
        $pattern1 = { 75 10 shr eax,08h jne 0041B909h }
        $pattern2 = { 76 20 shr eax,08h jne 0041B90Ah }

    condition:
        any of them
}