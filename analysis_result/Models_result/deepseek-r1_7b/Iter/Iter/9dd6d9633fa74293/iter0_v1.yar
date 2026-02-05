rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 FF 75 08 E8 C8 FF FF FF FF 75 08 FF 15 AC B0 41 00 }   // Push ebp, mov ebp, esp, call dword ptr [ebp+8h], pop ecx, push dword ptr [ebp+8h]
        $pattern1 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF FF 15 AC B0 41 00 }   // Alternative bypass with different register usage
        $pattern2 = { 8B FF 55 FF 75 08 FF 15 AC B0 41 00 FF 75 08 FF 75 08 }     // Different exit path without pop ecx

    condition:
        any of them
}