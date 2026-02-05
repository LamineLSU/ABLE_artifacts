rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC E8 C8 FF FF FF FF 59 }  // Trace //3 & //4: push ebp; mov ebp, esp; call 0040E7C3h; pop ecx
        $pattern1 = { FF 75 08 FF 15 AC B0 41 00 }  // Trace //4: push dword ptr [ebp+08h]; call dword ptr [0041B0ACh]
        $pattern2 = { FF 75 08 FF 15 8C E1 22 01 }  // Trace //5: push dword ptr [ebp+08h]; call dword ptr [0122E18Ch]

    condition:
        any of them
}