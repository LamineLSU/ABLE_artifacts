rule ExitProcessCall {
    meta:
        description = "Detects a call to ExitProcess (RtlExitUserProcess) with surrounding instructions."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 52 }  // push edx
        $b = { FF D0 }  // call eax
        $c = { 5E }  // pop esi
        $d = { 5D }  // pop ebp
        $e = { C3 }  // ret
    condition:
        $a and $b and $c and $d and $e
}

rule RtlFreeHeapCall {
    meta:
        description = "Detects a call to RtlFreeHeap with surrounding instructions."
    strings:
        $a = { 8B 45 ?? }  // mov eax, [ebp+??]
        $b = { FF D2 }  // call edx
        $c = { 85 C0 }  // test eax, eax
        $d = { 74 0A }  // je
    condition:
        $a and $b and $c and $d
}

rule ImulCheck {
    meta:
        description = "Detects an imul instruction with surrounding context."
    strings:
        $a = { 8B 4D ?? }  // mov ecx, [ebp+??]
        $b = { 0F AF 45 ?? }  // imul eax, [ebp+??]
        $c = { 85 C0 }  // test eax, eax
        $d = { 74 0A }  // je
    condition:
        $a and $b and $c and $d
}