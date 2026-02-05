rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF E8 C1 FF FF } // TEST EAX followed by JE/JNE
        $pattern1 = { 3D 00 10 00 00 0F 82 } // CMP and conditional jump
        $pattern2 = { 83 F8 01 74 12 FF E9 FF } // Specific comparison and conditional call bypass

    condition:
        any of them
}