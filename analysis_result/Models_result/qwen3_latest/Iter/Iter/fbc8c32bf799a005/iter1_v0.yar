rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 74 06 }  // Call to GetForegroundWindow followed by test eax, eax and je
        $pattern1 = { FF 15 ?? ?? ?? ?? 84 C0 74 0A }  // Call to GetCurrentProcessId followed by test al, al and je
        $pattern2 = { 0F B6 54 04 90 8D 44 24 0C }    // Loop instructions starting with movzx and subsequent movs

    condition:
        any of them
}