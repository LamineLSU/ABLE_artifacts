rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 A8 01 75 10 }  // test eax, eax; test al, 01h; jne
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // General call instruction (API check)
        $pattern2 = { FF 15 CC 01 6E 00 }  // Specific ExitProcess call

    condition:
        any of them
}