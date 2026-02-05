rule ExamplePattern
{
    meta:
        description = "Detects a test, conditional jump on zero, and call instruction pattern"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 85 C0 } // test eax, eax
        $b = { 0F 84 ?? ?? ?? ?? } // jz (conditional jump if zero)
        $c = { E8 ?? ?? ?? ?? } // call instruction

    condition:
        all of them
}