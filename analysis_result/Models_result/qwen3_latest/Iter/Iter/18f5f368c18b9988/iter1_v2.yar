rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 11 74 05 8B 45 FC }  // cmp eax,11h + je + mov
        $pattern1 = { FF 15 88 00 26 00 50 83 F8 11 }  // call VirtualAlloc + push + cmp
        $pattern2 = { 85 C0 0F 94 C0 58 85 FF }  // test eax, eax + setz + push + test edi

    condition:
        any of them
}