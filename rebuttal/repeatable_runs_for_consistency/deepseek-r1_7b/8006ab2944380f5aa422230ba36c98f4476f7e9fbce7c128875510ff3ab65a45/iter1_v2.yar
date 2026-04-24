rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific early call test"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 14 5B 7E 9D }  // TEST EAX and JE or JNE with specific offsets
        $pattern1 = { 8B 45 FC 5A F2 6C }  // Specific conditional move before exit call
        $pattern2 = { 83 C0 0F 84 7E FF 9D }  // Another TEST EAX with fixed offset
}

    condition:
        any of them
}