rule Bypass_Sample_Evolved {
    meta:
        description = "Bypass strategy targeting specific function calls and jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? ?? }  // Example: mov eax, dword ptr [ebp-8h]
        $pattern1 = { FF D2 ?? ?? ?? ?? ?? }  // Unconditional call to ExitProcess
        $pattern2 = { 3D 00 10 00 00 00 0F 82 }    // Specific offset move instruction

    condition:
        any of them
}