rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 45 FC }  // test eax, eax + je + mov [ebp-4]
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // call + test eax + je (offset wildcard)
        $pattern2 = { FF 15 ?? ?? ?? ?? 33 FF 8B 4D FC }  // call ExitProcess + xor edi + mov ecx [ebp-4]

    condition:
        any of them
}