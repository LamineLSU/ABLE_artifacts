rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 C8 FF FF FF }
        $pattern1 = { 3D ?? ?? ?? ?? 0F 82 ?? }  // cmp eax,imm32 + jb
        $pattern2 = { FF 15 AC B0 41 00 59 FF 75 ?? }  // call dword ptr [0041B0ACh]

    condition:
        any of them
}