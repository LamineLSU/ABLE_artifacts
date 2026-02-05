rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 2C A1 FA 00 } // push ebx + call ExitProcess
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? } // test eax, eax + je (offset wildcard)
        $pattern2 = { 8B CE E8 76 FA FF FF } // mov ecx, esi + call (specific offset)

    condition:
        any of them
}