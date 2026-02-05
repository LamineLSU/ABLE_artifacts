rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D B0 74 0C 00 00 56 50 56 50 E8 44 09 00 00 } // Target: 0041A24F - lea esi, dword ptr [eax+00000C74h]
        $pattern1 = { 56 6A 35 6A 00 51 8D B0 74 0C 00 00 } // Target: 0041A249 - push esi, push 0x35, push 0x00, push ecx
        $pattern2 = { 8B 55 14 8B 45 10 8B 4D 0C 83 C4 14 52 8B 16 50 51 FF D2 } // Target: 0041A25C - mov edx, dword ptr [ebp+14h] ... call edx

    condition:
        any of them
}