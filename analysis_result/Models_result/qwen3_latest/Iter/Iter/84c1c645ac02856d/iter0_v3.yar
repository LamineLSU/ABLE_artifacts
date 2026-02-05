rule Example_Malware_Signature
{
    meta:
        description = "Detects a sequence of instructions indicative of a known exploit or malware"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { B0 60 }          // mov al, 0x60
        $b = { 80 00 00 }       // or al, 0x00
        $c = { 0F B6 50 50 }    // add [esi+0x50], dl (this may need adjustment)
        $d = { 56 }             // push esi
        $e = { 50 }             // push eax
        $f = { E8 74 0A 00 00 } // call 0041EB77
    condition:
        all of ($a, $b, $c, $d, $e, $f)
}