rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific calls in trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3A 7C 45 84 ?? ?? ?? ?? }  // Targeting a specific call in the first trace
        $pattern1 = { 9D C6 D7 B7 07 2E 08 D6 F6 }  // Specific sequence from the second trace
        $pattern2 = { A4 AE 5E FE FF 4C 20 03 0F 45 }  // Unique instruction pattern from the first call
    condition:
        any of them
}