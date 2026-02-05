rule ExitProcessCheck
{
    meta:
        description = "Detects ExitProcess call with preceding check logic"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 50

    strings:
        $a = { E8 6E FF FF FF 6A 00 } // First call + push
        $b = { E8 2D 01 00 00 CC }     // ExitProcess call + int3
        $c = { 6A 00 E8 2D 01 00 00 } // Push + ExitProcess call

    condition:
        all of ($a, $b, $c)
}