rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B E8 F7 25 00 00 83 F8 01 74 12 8B 4D FC } // mov edi,edi; push ebp; mov ebp,esp; call 0041DF02h
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 } // mov eax,dword ptr fs:[00000030h]; mov eax,[eax+68h]
        $pattern2 = { FF 15 A0 F1 42 00 50 FF 15 40 F1 42 00 E8 0B 00 00 00 } // call dword ptr [0042F1A0h]; push eax; call dword ptr [0042F140h]

    condition:
        any of them
}