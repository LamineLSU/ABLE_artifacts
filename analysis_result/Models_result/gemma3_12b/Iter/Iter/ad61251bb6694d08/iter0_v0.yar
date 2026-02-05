rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - ExitProcess bypass"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 25 05 00 00 85 C0 }  // push 0x5B, pop edx, mov ecx, esi, call, test eax
        $pattern1 = { 8D 95 F0 FE FF FF 89 9D F0 FE FF FF 8B CE E8 74 FA FF FF 85 C0 } // lea, mov, mov, call, test
        $pattern2 = { FF 15 2C A1 15 01 33 FF 8B C7 EB 03 8D 43 01 } // call, xor, mov, jmp, lea

    condition:
        any of them
}