rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B CE } // test + je + mov (specific stack offset)
        $pattern1 = { 3D 00 10 00 00 0F 82 } // cmp eax,imm32 + jb (concrete comparison value)
        $pattern2 = { C3 E8 A5 FA FF FF } // ret + call (unique sequence after exit check)

    condition:
        any of them
}