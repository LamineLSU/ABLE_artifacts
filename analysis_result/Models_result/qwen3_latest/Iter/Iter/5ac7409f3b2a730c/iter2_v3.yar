rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE } // test eax, je, push 0x5B, pop edx, mov ecx, esi
        $pattern1 = { 50 53 FF 15 ?? ?? ?? ?? } // push eax, push ebx, call [00DDA12Ch]
        $pattern2 = { 8B CE E8 ?? ?? ?? ?? 85 C0 } // mov ecx, esi, call [00DD667Fh], test eax

    condition:
        any of them
}