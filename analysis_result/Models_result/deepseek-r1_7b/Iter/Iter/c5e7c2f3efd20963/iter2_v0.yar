rule Bypass_Evasion_1
{
    meta:
        description = "Evasion bypass patterns targeting stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? }  // After pushing EBP, mov eax, dword ptr [ebp-08h]
        $pattern1 = { FF 75 00 00 ?? }  // Conditional jump near
        $pattern2 = { 8B 4C 08 ?? ?? }  // Another stack manipulation pattern

    condition:
        any of them
}