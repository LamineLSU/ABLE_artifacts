rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B D0 85 C0 75 1D }  // mov edx, eax + test eax + jne
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // ExitProcess call (address wildcard)
        $pattern2 = { E8 7D AE 00 00 85 C0 }  // call + test eax sequence

    condition:
        any of them
}