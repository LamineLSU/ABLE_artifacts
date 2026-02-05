rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 FF 74 39 }  // WaitForMultipleObjects + test edi, edi + je
        $pattern1 = { FF 15 ?? ?? ?? ?? 83 3E 00 74 14 }  // CloseHandle + cmp [esi], 0 + je
        $pattern2 = { FF 15 ?? ?? ?? ?? }  // ExitProcess call (wildcard for address)

    condition:
        any of them
}