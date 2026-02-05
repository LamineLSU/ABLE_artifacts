rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D B0 A0 0C 00 00 56 50 E8 ?? 0A 00 00 }  // lea esi, dword ptr [eax+00000CA0h], push esi, push eax, call
        $pattern1 = { 8B 45 08 8B 88 18 0A 00 00 56 6A 36 } // mov eax, dword ptr [ebp+08h], mov ecx, dword ptr [eax+00000A18h], push esi, push 0x36
        $pattern2 = { 55 8B EC 8B 45 08 8B 88 18 0A 00 00 } // push ebp, mov ebp, esp, mov eax, dword ptr [ebp+08h], mov ecx, dword ptr [eax+00000A18h]

    condition:
        any of them
}