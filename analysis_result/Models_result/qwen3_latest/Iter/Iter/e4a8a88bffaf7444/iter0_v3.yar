rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 48 F2 FF FF E8 ?? ?? ?? ?? 8B D0 }  // mov eax, [ebp-00000DB8h] + call + mov edx, eax
        $pattern1 = { 5A E8 ?? ?? ?? ?? 8B 85 44 F2 FF FF }     // pop edx + call + mov eax, [ebp-00000DBCh]
        $pattern2 = { 6A 00 E8 ?? ?? ?? ?? 85 C0 }              // push 0 + call + test eax, eax

    condition:
        any of them
}