rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 75 07 ?? ?? }  // test eax, eax + jne (evasion check)
        $pattern1 = { 83 F8 11 74 05 ?? }  // cmp eax, 11h + je (validation)
        $pattern2 = { 33 C0 F3 AA ?? ?? }  // xor eax, eax + rep stosb (memory zeroing)

    condition:
        any of them
}