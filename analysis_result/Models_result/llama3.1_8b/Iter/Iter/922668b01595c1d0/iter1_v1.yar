rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D ?? ?? ?? ?? 0F 82 ?? ?? } // cmp eax,imm32 + jb
        $pattern1 = { 8B FF 55 8B EC E8 F7 ?? ?? ?? ?? 83 F8 01 74 12 } // mov edi,edi + push ebp + test
        $pattern2 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A0 01 } // mov eax,dword ptr fs:[00000030h] + shr

    condition:
        any of them
}