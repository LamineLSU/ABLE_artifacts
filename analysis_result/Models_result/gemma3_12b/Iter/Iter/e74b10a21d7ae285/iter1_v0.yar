rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 25 05 00 00 }  // push 0x5B; pop edx; ... call
        $pattern1 = { 85 C0 74 12 6A 5B } // test eax, eax; je; push 0x5B
        $pattern2 = { 8B 85 F0 FE FF FF } // mov eax, dword ptr [ebp-0x110]

    condition:
        any of them
}