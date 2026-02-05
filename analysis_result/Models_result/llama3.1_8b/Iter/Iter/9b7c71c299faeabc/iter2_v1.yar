rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? ?? ?? ?? ?? ?? ?? } // CALL instruction
        $pattern1 = { FF D2 8B EC 83 E4 F8 } // TEST EAX followed by conditional jump
        $pattern2 = { 75 ?? ?? ?? ?? ?? ?? ?? } // JE/JNE instruction

    condition:
        any of them
}