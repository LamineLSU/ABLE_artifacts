rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 DB BA 21 05 00 00 53 }  // XOR EBX, EBX + MOV EDX, 0x2105 + PUSH EBX
        $pattern1 = { FF 15 ?? ?? ?? ?? }         // CALL before ExitProcess (address varies)
        $pattern2 = { 6A 5B 85 C0 74 12 }         // PUSH 0x5B + TEST EAX + JE (offset fixed)

    condition:
        any of them
}