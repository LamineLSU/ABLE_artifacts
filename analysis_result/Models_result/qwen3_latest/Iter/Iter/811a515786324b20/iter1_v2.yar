rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { A1 64 B5 41 00 8B 00 FF D0 }  // mov eax, [0041B564h] + mov eax, [eax] + call eax
        $pattern1 = { 6A 00 E8 B4 AE FE FF }         // push 0 + call ExitProcess (offset varies)
        $pattern2 = { 8B 85 94 FD FF FF E8 F5 B9 FE FF }  // mov eax, [ebp-0000026Ch] + call (offset varies)

    condition:
        any of them
}