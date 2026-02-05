rule ProcessTerminationCheck {
    meta:
        description = "Detects potential process termination or cleanup routines."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 75 08 E8 C8 FF FF FF }  // First function call
        $b = { FF 75 08 FF 15 AC B0 41 00 }  // ExitProcess call
        $c = { 55 8B EC FF 75 08 }  // Function prologue
    condition:
        all of ($a, $b, $c)
}