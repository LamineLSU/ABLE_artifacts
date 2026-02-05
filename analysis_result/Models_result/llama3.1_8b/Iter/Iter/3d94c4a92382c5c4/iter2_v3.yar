rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? } // test + je
        $pattern1 = { 8B FF 55 8B EC E8 ?? ?? ?? ?? } // mov edi,edi + push ebp + call
        $pattern2 = { 64 A1 30 00 00 00 8B 40 68 } // mov eax,dword ptr fs:[00000030h] + mov eax,dword ptr [eax+68h]

    condition:
        any of them
}