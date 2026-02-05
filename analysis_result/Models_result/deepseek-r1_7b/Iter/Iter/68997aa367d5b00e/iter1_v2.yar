rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 0E } // TEST EAX followed by JE/JNE
        $pattern1 = { E8 B7 F7 FF FF E8 B7 F7 FF FF } // Conditional check before exit call
        $pattern2 = { E8 15 14 28 43 00 } // Potential bypass point after conditional checks

    condition:
        any of them
}