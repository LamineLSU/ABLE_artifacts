rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 8B 45 ?? } // Trace //1 - test eax, je, test eax, mov ecx, esi
        $pattern1 = { 53 6A 40 53 68 40 11 31 01 } // Trace //1 - push ebx, push 0x40, push ebx, push 0x40113101
        $pattern2 = { E8 C8 FF FF FF 59 FF 75 08 } // Trace //2 & 3 - call, pop ecx, push dword ptr [ebp+08h]

    condition:
        any of them
}