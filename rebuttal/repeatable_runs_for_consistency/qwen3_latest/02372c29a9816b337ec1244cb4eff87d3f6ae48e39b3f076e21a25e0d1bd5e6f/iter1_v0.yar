rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 05 00 00 85 C0 0F 84 ?? FD FF FF }  // Call to 00EC667Fh, test eax, je
        $pattern1 = { E8 74 FA FF FF 85 C0 0F 84 ?? FD FF FF }  // Call to 00EC5C17h, test eax, je
        $pattern2 = { 85 C0 0F 84 ?? FD FF FF }             // Direct test eax, je (no call)

    condition:
        any of them
}