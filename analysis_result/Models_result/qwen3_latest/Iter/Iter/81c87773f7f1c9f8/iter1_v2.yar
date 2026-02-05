rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B CE }  // test eax, eax + je + mov ecx, esi
        $pattern1 = { FF 15 88 A0 04 01 }   // call dword ptr [0104A088h]
        $pattern2 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF }  // lea + mov (ebp-0x110)

    condition:
        any of them
}