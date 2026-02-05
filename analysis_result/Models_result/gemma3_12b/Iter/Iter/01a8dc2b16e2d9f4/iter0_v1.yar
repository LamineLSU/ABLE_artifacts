rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 } // Trace //1 - MOV EDI,EDI; PUSH EBP; MOV EBP,ESP; PUSH dword ptr [ebp+08h]
        $pattern1 = { E8 C8 FF FF FF 59 FF 75 08 } // Trace //2 & 4 - CALL 0040E7C3h; POP ECX; PUSH dword ptr [ebp+08h]
        $pattern2 = { FF 15 AC B0 41 00 FF 15 AC B0 41 00 } // Trace //4 - CALL dword ptr [0041B0ACh]; CALL dword ptr [0041B0ACh]

    condition:
        any of them
}