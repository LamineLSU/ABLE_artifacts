rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }   // test+je+mov (specific stack offset)
        $pattern1 = { B9 00 10 00 00 E8 8B 4D F8 }          // cmp eax,imm32 + jb
        $pattern2 = { 0F A3 44 ?? ?? ?? ?? }                 // vmread rax, [rdi+0x????]

    condition:
        any of them
}