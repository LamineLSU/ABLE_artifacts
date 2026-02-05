rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 85 C0 0F 84 ?? ?? ?? ?? } // mov eax,[ebp-4] test eax, eax je near ptr
        $pattern1 = { 3D 00 10 00 00 0F 82 ?? ?? ?? ?? } // cmp eax,imm32 jb near ptr
        $pattern2 = { FF D0 E8 00 00 00 00 } // call DWORD PTR [eax] ret

    condition:
        any of them
}