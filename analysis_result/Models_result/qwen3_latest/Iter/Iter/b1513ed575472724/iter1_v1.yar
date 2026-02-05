rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 25 00 00 83 F8 01 74 20 }  // CALL -> CMP EAX -> JE
        $pattern1 = { 8B 40 68 C1 E8 08 A8 01 75 10 }  // MOV EAX [eax+68h] -> SHR -> TEST AL -> JNE
        $pattern2 = { FF 15 ?? F1 42 00 }             // CALL TerminateProcess@KERNEL32

    condition:
        any of them
}