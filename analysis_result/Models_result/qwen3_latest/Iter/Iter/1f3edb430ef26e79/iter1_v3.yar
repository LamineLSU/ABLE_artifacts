rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 14 52 FF D0 }  // add esp, 14h; push edx; call eax (ExitProcess)
        $pattern1 = { E8 74 0A 00 00 8B 55 14 }  // call 0041EB47h; mov edx, [ebp+14h]
        $pattern2 = { 8B 45 08 8B 88 18 0A 00 00 }  // mov eax, [ebp+08h]; mov ecx, [eax+0A18h]

    condition:
        any of them
}