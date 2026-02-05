rule Sample_Evasion
{
    meta:
        description = "Detects evasion via memory management and FPU obfuscation"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,count=0"
    strings:
        $a = { ?? ?? ?? ?? ?? ?? FF D2 5E 5D C3 } // RtlAllocateHeap + stack cleanup
        $b = { ?? ?? ?? ?? ?? FF D2 C3 } // RtlFreeHeap + direct return
        $c = DC8BB6FA9197 // FPU instruction for obfuscation
    condition:
        all of ($a, $b, $c)
}