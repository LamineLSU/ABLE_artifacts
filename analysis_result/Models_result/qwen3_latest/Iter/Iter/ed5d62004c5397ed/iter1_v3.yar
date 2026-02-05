rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B } // test eax, eax + je + push
        $pattern1 = { 8B CE E8 25 05 00 00 } // mov ecx, esi + call
        $pattern2 = { B9 42 8C E2 00 50 E8 E3 FA FF FF } // mov ecx, imm + push + call

    condition:
        any of them
}