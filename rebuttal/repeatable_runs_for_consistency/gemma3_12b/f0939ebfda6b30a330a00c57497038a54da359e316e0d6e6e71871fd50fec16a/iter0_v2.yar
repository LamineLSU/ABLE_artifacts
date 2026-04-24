rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Bypass Call 3"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { 83 26 00 83 C6 04 8B 45 C4 }
        // and dword ptr [esi], 00000000h, add esi, 04h, mov eax, dword ptr [ebp-3Ch]

    condition:
        any of them
}