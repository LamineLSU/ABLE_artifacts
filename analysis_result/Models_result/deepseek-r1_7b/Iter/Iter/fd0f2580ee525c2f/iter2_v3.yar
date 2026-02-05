rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting TEST EAX followed by conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 25 05 00 00 }  // TEST EAX followed by JE
        $pattern1 = { 3D 00 10 00 00 00 0F 84 ?? ?? }  // CMP withimm and JB/SJMP
        $pattern2 = { 74 12 6A 5B E8 74 FA FF FF }  // TEST EAX followed by different jump

    condition:
        (any of the patterns match in the first 30% of trace) || (patterns matched but not at exit calls)
}