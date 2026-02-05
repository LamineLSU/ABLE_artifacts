rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 4C 55 }  // mov edi, edi; push ebp; mov ebp, esp
        $pattern1 = { E8 C8 FF FF 59 }  // call dword ptr [ebp+08h]; pop ecx
        $pattern2 = { FF 75 08 39 6A }  // push dword ptr [ebp+08h]; add word ptr [ebp-4h]
}

condition:
    any of them
}