rule test_eax_eax_jne {
    meta:
        description = "Test EAX and jump if not equal"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 85 C0 } // test eax, eax
        $b = { 75 04 } // jne 0x401008
        $c = { 31 C0 } // xor eax, eax
        $d = { C3 }    // ret
    condition:
        $a and $b and $c and $d
}