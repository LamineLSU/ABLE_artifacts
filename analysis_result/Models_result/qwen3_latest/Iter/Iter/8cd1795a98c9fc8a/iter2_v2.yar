rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }  // CALL + CMP+JE evasion check
        $pattern1 = { FF 15 40 F1 42 00 }                // TerminateProcess API call
        $pattern2 = { 8B 40 68 C1 E8 08 A8 01 }          // Unique register manipulation sequence

    condition:
        any of them
}