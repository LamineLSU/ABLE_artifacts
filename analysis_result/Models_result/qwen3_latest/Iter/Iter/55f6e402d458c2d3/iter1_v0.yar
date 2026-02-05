rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 3C 22 75 ?? }  // Call GetCommandLineA + CMP AL, 22h + JNE
        $pattern1 = { 8A 01 3C 20 7F 07 }                // MOV AL, [ECX] + CMP AL, 20h + JNLE
        $pattern2 = { FF 15 EC 41 41 00 }               // Call GetStartupInfoA

    condition:
        any of them
}