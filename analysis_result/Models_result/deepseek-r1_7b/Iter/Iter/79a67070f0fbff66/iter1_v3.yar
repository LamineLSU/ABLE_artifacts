rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - target conditional checks before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 C4 FF 15 9C 50 61 00 E8 5F 88 00 00 } // mov eax, dword ptr... followed by call dword ptr...
        $pattern1 = { 83 E8 00 8B 4D 80 C7 45 C4 F8 8D 9A FF FF } // conditional move and jump
        $pattern2 = { 83 F6 00 FF 15 E4 FF 15 FC } // compare and jump based on EAX value
    condition:
        any of them
}