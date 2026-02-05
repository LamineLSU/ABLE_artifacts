rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 ?? ?? ?? ?? 74 07 }  // Skip CloseHandle call and subsequent je
        $pattern1 = { A1 88 85 CB 00 85 C0 74 07 }      // Skip test eax, eax and je after CloseHandle
        $pattern2 = { E8 25 05 00 00 85 C0 74 12 }      // Skip initial test and je to ExitProcess

    condition:
        any of them
}