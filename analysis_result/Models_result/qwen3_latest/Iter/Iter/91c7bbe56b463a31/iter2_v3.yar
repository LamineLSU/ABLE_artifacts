rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 BC 24 50 06 00 00 06 74 4C } // CMP EAX, 06h + JE
        $pattern1 = { FF 15 74 30 42 00 83 BC 24 50 06 00 00 06 } // CALL GetVersionExA + CMP EAX, 06h
        $pattern2 = { FF 15 88 30 42 00 83 BC 24 50 FF 00 00 00 75 0A } // CALL GetFileAttributesA + CMP EAX, FFh + JNE

    condition:
        any of them
}