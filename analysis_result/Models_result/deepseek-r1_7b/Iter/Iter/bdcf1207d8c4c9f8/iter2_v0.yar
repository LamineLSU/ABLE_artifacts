rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting specific call instructions"
        cape_options = "bp0=$pattern0,action0=skip,bp1=$pattern1,action1=skip,bp2=$pattern2,count=0"

    strings:
        $pattern0 = { 8B FF C8 E8 ??.?? } // mov edi, edi; push ebp; push dword ptr [ebp+08h]; call target
        $pattern1 = { 55 FF C8 E8 ??.?? } // mov rsi, rdi; push ebp; push dword ptr [ebp+08h]; call target
        $pattern2 = { FF00 C8 E8 ??.?? } // push ebp directly; push dword ptr [ebp+08h]; call target

    condition:
        any of them
}