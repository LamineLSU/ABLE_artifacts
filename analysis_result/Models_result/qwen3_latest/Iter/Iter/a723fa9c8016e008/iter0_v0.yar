rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx + call ExitProcess
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test eax + conditional jump
        $pattern2 = { 33 C9 E8 ?? ?? ?? ?? }  // Xor ecx + call (evasion check)

    condition:
        any of them
}