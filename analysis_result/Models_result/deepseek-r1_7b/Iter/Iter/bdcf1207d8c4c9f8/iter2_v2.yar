rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 C8 FF ?? } // After push dword ptr [ebp+08h] followed by call
        $pattern1 = { 59 FF 75 08 E8 C8 ?? } // After pop ecx and another push dword ptr [ebp+08h]
        $pattern2 = { E8 C8 F6 FF 75 08 } // Call with offset followed by push dword ptr
    condition:
        any of them
}