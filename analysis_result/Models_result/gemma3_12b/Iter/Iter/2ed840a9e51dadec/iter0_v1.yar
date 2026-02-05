rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 } // mov edi, edi; push ebp; mov ebp, esp; push dword ptr [ebp+08h] (TRACE //4)
        $pattern1 = { 8B FF 55 8B EC E8 07 26 00 00 } // mov edi, edi; push ebp; mov ebp, esp; call 0022CFB2h (TRACE //5)
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // push ??; pop ecx; mov ebp, esp; call 0022A9E3h; cmp eax, 01h; test eax, 01h (TRACE //5)

    condition:
        any of them
}