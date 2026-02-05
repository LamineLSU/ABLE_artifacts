rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A }  // test eax, eax; je; push; pop
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 }  // call to function; test eax, eax
        $pattern2 = { 50 FF 15 ?? ?? ?? ?? }  // push; call to API (CloseHandle)

    condition:
        any of them
}