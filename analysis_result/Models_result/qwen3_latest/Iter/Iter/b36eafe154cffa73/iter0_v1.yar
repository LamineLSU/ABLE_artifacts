rule MemoryAllocationCheck {
    meta:
        description = "Detects memory allocation check and exit logic"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 15 78 7C 42 00 83 7D FC 00 75 08 }
        $b = { 6A 00 FF 15 88 7C 42 00 }
        $c = { 83 7D FC 00 75 08 }
    condition:
        any of ($a, $b, $c)
}