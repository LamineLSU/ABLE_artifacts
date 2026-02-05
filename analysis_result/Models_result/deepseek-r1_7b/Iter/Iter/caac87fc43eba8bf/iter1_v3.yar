rule Bypass_Sample {
    meta:
        description = "Evasion bypass targeting specific call points in a malicious execution path"
        cape_options = "bp0=$pattern0+0,bp1=$pattern1+0,bp2=$pattern2+0,action0=skip,action1=skip,action2=skip,count=0"

    strings:
        $pattern0 = { 55 C7 FF 8B EC E8 C8 FF FF FF } // Push ebp; mov esp, ebp; call E7C3h
        $pattern1 = { 55 20 45 FF 15 AC B0 41 00 } // Push dword ptr [ebp+08h]; call FF15ACB04100
        $pattern2 = { 05 5A 55 20 45 FF C4 6D 97 } // Pop ebp; push dword ptr [ebp+08h with displacement 0x3C]; perform an action

    condition:
        any of them
}