rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 F4 63 45 00 85 C0 74 16 }  // GetModuleHandleA check
        $pattern1 = { FF 15 F8 63 45 00 85 C0 74 16 }  // GetProcAddress check
        $pattern2 = { FF 74 24 04 FF D0 }                // Pre-ExitProcess push+call

    condition:
        any of them
}