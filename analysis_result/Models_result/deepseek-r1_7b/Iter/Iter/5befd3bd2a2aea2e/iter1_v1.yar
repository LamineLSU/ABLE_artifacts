rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences in the exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [0x8b ff] }
        $pattern1 = { [E8C8FFFFFF] }
        $pattern2 = { [FF7508] }

    condition:
        any of them
}