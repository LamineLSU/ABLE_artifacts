rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 14 52 E8 ?? ?? ?? ?? FF D0 }  // add esp,14h + push edx + call RtlFreeHeap + call ExitProcess
        $pattern1 = { E8 ?? ?? ?? ?? 8B 45 ?? FF D0 }      // call RtlFreeHeap + mov eax, [ebp+??] + call ExitProcess
        $pattern2 = { 8B 45 ?? 85 C0 74 ?? FF D0 }         // mov eax, [ebp+??] + test eax + jz + call ExitProcess

    condition:
        any of them
}