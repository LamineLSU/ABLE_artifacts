rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 50 51 6A 35 6A 00 }  // push esi, push eax, push ecx, push 0x35, push 0x00
        $pattern1 = { 56 50 51 6A 00 51 8D B0 }  // push esi, push eax, push ecx, push 0x00, push ecx, lea esi
        $pattern2 = { 55 8B EC 8B 45 08 8B 48 10 }  // push ebp, mov ebp, esp, mov eax, dword ptr [ebp+08h], mov ecx, dword ptr [eax+10h]

    condition:
        any of them
}