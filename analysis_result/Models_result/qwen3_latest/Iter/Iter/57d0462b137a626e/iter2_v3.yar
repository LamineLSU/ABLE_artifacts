rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE }  // Early test+je + push/pop/mov
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // Call followed by test+je
        $pattern2 = { FF 15 88 A0 16 00 }  // CloseHandle call before ExitProcess

    condition:
        any of them
}