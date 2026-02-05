rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF 59 } // CALL to test function
        $pattern1 = { 3D 00 10 00 00 0F 82 } // cmp eax,imm32 + jb (concrete comparison value)
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC } // test+je+mov (specific stack offset)

    condition:
        any of them
}