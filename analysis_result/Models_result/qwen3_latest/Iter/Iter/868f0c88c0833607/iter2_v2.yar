rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 85 C0 74 12 }  // mov eax, [ebp-04] + test + je
        $pattern1 = { 8B 45 F8 85 C0 0F 84 ?? ?? ?? ?? }  // mov eax, [ebp-08] + test + je (variable offset)
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? }  // push ebx + call ExitProcess (RVA wildcard)

    condition:
        any of them
}