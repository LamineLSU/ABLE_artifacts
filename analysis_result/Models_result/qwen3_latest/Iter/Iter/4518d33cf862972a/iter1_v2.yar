rule ExampleRule {
    meta:
        description = "Detects specific instruction patterns from the provided memory dump"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 8B D0 }  // mov edx, eax
        $b = { 85 C0 }  // test eax, eax
        $c = { 75 1D }  // jne 0x1D
    condition:
        all of them
}