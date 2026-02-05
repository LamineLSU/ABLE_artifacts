rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }  // test eax, eax + je + mov [ebp-04h]
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // call + test eax, eax + je
        $pattern2 = { FF 15 2C A1 06 00 }  // call dword ptr [0006A12Ch] (ExitProcess)

    condition:
        any of them
}