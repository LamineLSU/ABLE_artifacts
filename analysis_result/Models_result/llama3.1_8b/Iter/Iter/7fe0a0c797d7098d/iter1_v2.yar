rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D F8 }  // cmp+je+mov (concrete bytes)
        $pattern1 = { C3 4C 21 FF FF 75 14 D9 2A }  // call+test+jne+rtdsc (unique sequence)
        $pattern2 = { B8 01 00 00 00 EB 03 C7 45 FC 02 }  // mov eax,+jmp (cpu id vm detection)

    condition:
        any of them
}