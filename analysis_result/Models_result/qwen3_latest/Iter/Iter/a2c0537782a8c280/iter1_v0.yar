rule HeapOperations {
    meta:
        description = "Detects heap allocation and deallocation operations involving NTDLL functions."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF D6 8B 45 FC E8 ?? ?? ?? ?? }
        $b = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $c = { 8B 45 FC E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 }
    condition:
        any of them
}