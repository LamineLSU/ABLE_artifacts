rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { FF 15 F1 0E 00 00 }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }  // concrete bytes for comparison
        $pattern2 = { 3D 00 10 00 00 0F 82 }  // cmp eax,imm32 + jb (concrete comparison value)

    condition:
        any of them
}