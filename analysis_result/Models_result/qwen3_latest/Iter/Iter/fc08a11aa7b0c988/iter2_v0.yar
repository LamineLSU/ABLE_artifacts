rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { ?? ?? ?? ?? ?? 85 C0 74 10 }  // Test EAX and conditional jump
        $pattern1 = { ?? ?? ?? ?? ?? ?? 83 7D 10 00 75 32 }  // CMP and JNE check
        $pattern2 = { ?? ?? ?? ?? ?? ?? ?? ?? FF 15 24 01 41 00 }  // ExitProcess call

    condition:
        any of them
}